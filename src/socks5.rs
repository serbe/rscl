use std::{
    convert::{From, TryFrom},
    net::{Ipv4Addr, Ipv6Addr},
    u8,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::{Host, Url};

use crate::consts;
use crate::error::{Error, Result};

#[derive(Clone, Copy, PartialEq)]
pub enum Command {
    TCPConnection,
    TCPBinding,
    UDPPort,
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::TCPConnection => consts::SOCKS5_COMMAND_TCP_CONNECT,
            Command::TCPBinding => consts::SOCKS5_COMMAND_TCP_BIND,
            Command::UDPPort => consts::SOCKS5_COMMAND_UDP_ASSOCIATE,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            consts::SOCKS5_COMMAND_TCP_CONNECT => Ok(Command::TCPConnection),
            consts::SOCKS5_COMMAND_TCP_BIND => Ok(Command::TCPBinding),
            consts::SOCKS5_COMMAND_UDP_ASSOCIATE => Ok(Command::UDPPort),
            v => Err(Error::CommandUnknown(v)),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth,
    GSSAPI,
    Plain,
    NoAccept,
}

impl Into<u8> for AuthMethod {
    fn into(self) -> u8 {
        match self {
            AuthMethod::NoAuth => consts::SOCKS5_AUTH_NONE,
            AuthMethod::GSSAPI => consts::SOCKS5_AUTH_GSSAPI,
            AuthMethod::Plain => consts::SOCKS5_AUTH_USER_PASSWORD,
            AuthMethod::NoAccept => consts::SOCKS5_AUTH_NO_ACCEPT,
        }
    }
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            consts::SOCKS5_AUTH_NONE => Ok(AuthMethod::NoAuth),
            consts::SOCKS5_AUTH_GSSAPI => Ok(AuthMethod::GSSAPI),
            consts::SOCKS5_AUTH_USER_PASSWORD => Ok(AuthMethod::Plain),
            consts::SOCKS5_AUTH_NO_ACCEPT => Ok(AuthMethod::NoAccept),
            v => Err(Error::MethodUnknown(v)),
        }
    }
}

/// Client auth request
///
/// ```plain
/// The client connects to the server, and sends a version
/// identifier/method selection message:
///
///                 +----+----------+----------+
///                 |VER | NMETHODS | METHODS  |
///                 +----+----------+----------+
///                 | 1  |    1     | 1 to 255 |
///                 +----+----------+----------+
///
/// The VER field is set to X'05' for this version of the protocol.  The
/// NMETHODS field contains the number of method identifier octets that
/// appear in the METHODS field.
/// ```
/// #[derive(Clone, Debug)]
struct AuthRequest {
    pub ver: u8,
    pub nmethods: u8,
    pub methods: Vec<AuthMethod>,
}

impl AuthRequest {
    fn default() -> Self {
        AuthRequest {
            ver: consts::SOCKS5_VERSION,
            nmethods: 0u8,
            methods: Vec::new(),
        }
    }

    fn add_method(&mut self, method: AuthMethod) {
        if !self.methods.contains(&method) {
            self.nmethods += 1;
            self.methods.push(method);
        }
    }

    fn new(method: AuthMethod) -> Self {
        let mut auth_request = AuthRequest::default();
        auth_request.add_method(method);
        auth_request
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.nmethods);
        for method in &self.methods {
            buf.push(method.clone().into());
        }
        buf
    }

    // Send auth request to server
    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Server auth response
///
/// ```plain
/// The server selects from one of the methods given in METHODS, and
/// sends a METHOD selection message:
///
///                       +----+--------+
///                       |VER | METHOD |
///                       +----+--------+
///                       | 1  |   1    |
///                       +----+--------+
///
/// If the selected METHOD is X'FF', none of the methods listed by the
/// client are acceptable, and the client MUST close the connection.
///
/// The values currently defined for METHOD are:
///
///        o  X'00' NO AUTHENTICATION REQUIRED
///        o  X'01' GSSAPI
///        o  X'02' USERNAME/PASSWORD
///        o  X'03' to X'7F' IANA ASSIGNED
///        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
///        o  X'FF' NO ACCEPTABLE METHODS
///
/// The client and server then enter a method-specific sub-negotiation.
/// Descriptions of the method-dependent sub-negotiations appear in
/// separate memos.
///
/// Developers of new METHOD support for this protocol should contact
/// IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
/// referred to for a current list of METHOD numbers and their
/// corresponding protocols.
/// ```
struct AuthResponse {
    ver: u8,
    method: AuthMethod,
}

impl AuthResponse {
    async fn read(stream: &mut TcpStream) -> Result<Self> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let ver = buf[0];
        let method = AuthMethod::try_from(buf[1])?;
        if ver != consts::SOCKS5_VERSION {
            Err(Error::NotSupportedSocksVersion(ver))
        } else {
            match method {
                AuthMethod::NoAuth | AuthMethod::Plain => Ok(AuthResponse { ver, method }),
                AuthMethod::GSSAPI => Err(Error::Unimplement),
                AuthMethod::NoAccept => Err(Error::MethodNotAccept),
            }
        }
    }

    fn check(&self, method: AuthMethod) -> Result<()> {
        if self.method != method {
            Err(Error::MethodWrong)
        } else if self.ver != consts::SOCKS5_VERSION {
            Err(Error::NotSupportedSocksVersion(self.ver))
        } else {
            Ok(())
        }
    }
}

/// Auth with username and password
///
/// ```plain
/// Once the SOCKS V5 server has started, and the client has selected the
/// Username/Password Authentication protocol, the Username/Password
/// subnegotiation begins.  This begins with the client producing a
/// Username/Password request:
///
///         +----+------+----------+------+----------+
///         |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
///         +----+------+----------+------+----------+
///         | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
///         +----+------+----------+------+----------+
///
/// The VER field contains the current version of the subnegotiation,
/// which is X'01'. The ULEN field contains the length of the UNAME field
/// that follows. The UNAME field contains the username as known to the
/// source operating system. The PLEN field contains the length of the
/// PASSWD field that follows. The PASSWD field contains the password
/// association with the given UNAME.
/// ```
struct UserPassRequest {
    ver: u8,
    ulen: usize,
    uname: Vec<u8>,
    plen: usize,
    passwd: Vec<u8>,
}

impl UserPassRequest {
    fn new(username: &str, password: &str) -> Result<UserPassRequest> {
        let ver = 1u8;
        let uname = username.as_bytes().to_vec();
        let passwd = password.as_bytes().to_vec();
        match (uname.len(), passwd.len()) {
            (u, _) if u > 255 => Err(Error::UnameLenOverflow(u)),
            (_, p) if p > 255 => Err(Error::PasswdLenOverflow(p)),
            (ulen, plen) => Ok(UserPassRequest {
                ver,
                ulen,
                uname,
                plen,
                passwd,
            }),
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.ulen as u8);
        buf.extend_from_slice(&self.uname);
        buf.push(self.plen as u8);
        buf.extend_from_slice(&self.passwd);
        buf
    }

    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Check plain auth response
///
/// ```plain
///    The server verifies the supplied UNAME and PASSWD, and sends the
///    following response:
///
///                         +----+--------+
///                         |VER | STATUS |
///                         +----+--------+
///                         | 1  |   1    |
///                         +----+--------+
///
///    A STATUS field of X'00' indicates success. If the server returns a
///    `failure' (STATUS value other than X'00') status, it MUST close the
///    connection.
/// ```
struct UserPassResponse {
    ver: u8,
    status: u8,
}

impl UserPassResponse {
    async fn read(stream: &mut TcpStream) -> Result<UserPassResponse> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        Ok(UserPassResponse {
            ver: buf[0],
            status: buf[1],
        })
    }

    fn check(&self) -> Result<()> {
        if self.ver != 1u8 {
            Err(Error::NotSupportedVersion(self.ver))
        } else if self.status != 0u8 {
            Err(Error::WrongStatus(self.status))
        } else {
            Ok(())
        }
    }
}

/// Client to socks request
///
/// ```plain
/// The SOCKS request is formed as follows:
///
/// +----+-----+-------+------+----------+----------+
/// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
/// +----+-----+-------+------+----------+----------+
/// | 1  |  1  | X'00' |  1   | Variable |    2     |
/// +----+-----+-------+------+----------+----------+
///
/// Where:
///
///   o  VER    protocol version: X'05'
///   o  CMD
///      o  CONNECT X'01'
///      o  BIND X'02'
///      o  UDP ASSOCIATE X'03'
///   o  RSV    RESERVED
///   o  ATYP   address type of following address
///      o  IP V4 address: X'01'
///      o  DOMAINNAME: X'03'
///      o  IP V6 address: X'04'
///   o  DST.ADDR       desired destination address
///   o  DST.PORT desired destination port in network octet
///      order
///
/// The SOCKS server will typically evaluate the request based on source
/// and destination addresses, and return one or more reply messages, as
/// appropriate for the request type.
/// ```
struct SocksRequest {
    ver: u8,
    cmd: Command,
    rsv: u8,
    dst_addr: Host,
    dst_port: u16,
}

impl SocksRequest {
    fn new(command: Command, url: &Url) -> Result<SocksRequest> {
        let dst_addr = url.host().ok_or(Error::ParseAddr)?.to_owned();
        let dst_port = url.port_or_known_default().ok_or(Error::UnknownPort)?;
        Ok(SocksRequest {
            ver: consts::SOCKS5_VERSION,
            cmd: command,
            rsv: 0u8,
            dst_addr,
            dst_port,
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.cmd.into());
        buf.push(self.rsv);
        buf.push(addr_type(&self.dst_addr));
        for method in host_vec(&self.dst_addr) {
            buf.push(method);
        }
        buf.push(((self.dst_port >> 8) & 0xff) as u8);
        buf.push((self.dst_port & 0xff) as u8);
        buf
    }

    async fn send(&self, stream: &mut TcpStream) -> Result<()> {
        let buf = self.to_vec();
        stream.write_all(&buf).await?;
        Ok(())
    }
}

pub struct ServerBound {
    pub addr: Host,
    pub port: u16,
}

/// Read socks replies
///
/// ```plain
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
///      +----+-----+-------+------+----------+----------+
///      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///      +----+-----+-------+------+----------+----------+
///      | 1  |  1  | X'00' |  1   | Variable |    2     |
///      +----+-----+-------+------+----------+----------+
///
///   Where:
///
///        o  VER    protocol version: X'05'
///        o  REP    Reply field:
///           o  X'00' succeeded
///           o  X'01' general SOCKS server failure
///           o  X'02' connection not allowed by ruleset
///           o  X'03' Network unreachable
///           o  X'04' Host unreachable
///           o  X'05' Connection refused
///           o  X'06' TTL expired
///           o  X'07' Command not supported
///           o  X'08' Address type not supported
///           o  X'09' to X'FF' unassigned
///        o  RSV    RESERVED
///        o  ATYP   address type of following address
///           o  IP V4 address: X'01'
///           o  DOMAINNAME: X'03'
///           o  IP V6 address: X'04'
///        o  BND.ADDR       server bound address
///        o  BND.PORT       server bound port in network octet order
///
/// Fields marked RESERVED (RSV) must be set to X'00'.
///
/// If the chosen method includes encapsulation for purposes of
/// authentication, integrity and/or confidentiality, the replies are
/// encapsulated in the method-dependent encapsulation.
/// ```
struct SocksReplies {
    ver: u8,
    rep: u8,
    rsv: u8,
    atyp: u8,
}

impl SocksReplies {
    async fn read(stream: &mut TcpStream) -> Result<SocksReplies> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        Ok(SocksReplies {
            ver: buf[0],
            rep: buf[1],
            rsv: buf[2],
            atyp: buf[3],
        })
    }

    async fn get_addr(&self, stream: &mut TcpStream) -> Result<ServerBound> {
        if self.ver != consts::SOCKS5_VERSION {
            return Err(Error::NotSupportedSocksVersion(self.ver));
        }
        let _ = check_reply(self.rep)?;
        if self.rsv != 0u8 {
            return Err(Error::WrongReserved(self.rsv));
        }
        let addr: Host = match self.atyp {
            consts::SOCKS5_ADDRESS_TYPE_IPV4 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                Ok(Host::Ipv4(Ipv4Addr::from(buf)))
            }
            consts::SOCKS5_ADDRESS_TYPE_IPV6 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                Ok(Host::Ipv6(Ipv6Addr::from(buf)))
            }
            consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME => {
                let mut buf = [0u8];
                stream.read_exact(&mut buf).await?;
                let mut buf = Vec::with_capacity(buf[0] as usize);
                stream.read_exact(&mut buf).await?;
                Ok(Host::Domain(String::from_utf8(buf)?))
            }
            u => Err(Error::AddressTypeNotSupported(u)),
        }?;
        let port = stream.read_u16().await?;
        Ok(ServerBound { addr, port })
    }
}

fn check_reply(value: u8) -> Result<()> {
    match value {
        consts::SOCKS5_REPLY_SUCCESS => Ok(()),
        consts::SOCKS5_REPLY_GENERAL_SERVER_FAILURE => Err(Error::ReplyGeneralFailure),
        consts::SOCKS5_REPLY_CONNECTION_NOT_ALLOWED => Err(Error::ReplyConnectionNotAllowed),
        consts::SOCKS5_REPLY_NETWORK_UNREACHABLE => Err(Error::ReplyNetworkUnreachable),
        consts::SOCKS5_REPLY_HOST_UNREACHABLE => Err(Error::ReplyHostUnreachable),
        consts::SOCKS5_REPLY_CONNECTION_REFUSED => Err(Error::ReplyConnectionRefused),
        consts::SOCKS5_REPLY_TTL_EXPIRED => Err(Error::ReplyTtlExpired),
        consts::SOCKS5_REPLY_COMMAND_NOT_SUPPORTED => Err(Error::ReplyCommandNotSupported),
        consts::SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED => Err(Error::ReplyAddressTypeNotSupported),
        v => Err(Error::ReplyUnassigned(v)),
    }
}

pub async fn connect(proxy_str: &str, target_str: &str) -> Result<TcpStream> {
    connect_uri(&proxy_str.parse()?, &target_str.parse()?).await
}

pub async fn connect_plain<P, T>(
    proxy_str: &str,
    target_str: &str,
    username: &str,
    password: &str,
) -> Result<TcpStream> {
    let mut proxy: Url = proxy_str
        .parse::<Url>()?;
    proxy.set_username(username).map_err(|_| Error::BadUsername)?;
    proxy.set_password(if password.is_empty() { None} else { Some(password)}).map_err(|_| Error::BadPassword)?;
    connect_uri(&proxy, &target_str.parse()?).await
}

pub async fn connect_uri(proxy: &Url, target: &Url) -> Result<TcpStream> {
    let socket_address = proxy.socket_addrs(|| None)?.pop().ok_or(Error::SocketAddr)?;
    let mut stream =
        TcpStream::connect(socket_address).await?;
    if proxy.has_authority() {
        let username = proxy.username();
        let password = proxy.password().map_or("", |v| v);
        AuthRequest::new(AuthMethod::Plain)
            .send(&mut stream)
            .await?;
        AuthResponse::read(&mut stream)
            .await?
            .check(AuthMethod::Plain)?;
        UserPassRequest::new(&username, &password)?
            .send(&mut stream)
            .await?;
        UserPassResponse::read(&mut stream).await?.check()?;
    } else {
        AuthRequest::new(AuthMethod::NoAuth)
            .send(&mut stream)
            .await?;
        AuthResponse::read(&mut stream)
            .await?
            .check(AuthMethod::NoAuth)?;
    }
    SocksRequest::new(Command::TCPConnection, &target)?
        .send(&mut stream)
        .await?;
    SocksReplies::read(&mut stream)
        .await?
        .get_addr(&mut stream)
        .await?;
    Ok(stream)
}

pub fn addr_type(addr: &Host) -> u8 {
    match addr {
        Host::Ipv4(_) => consts::SOCKS5_ADDRESS_TYPE_IPV4,
        Host::Ipv6(_) => consts::SOCKS5_ADDRESS_TYPE_IPV6,
        Host::Domain(_) => consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME,
    }
}

fn host_vec(host: &Host) -> Vec<u8> {
    match host {
        Host::Ipv4(ipv4) => ipv4.octets().to_vec(),
        Host::Ipv6(ipv6) => ipv6.octets().to_vec(),
        Host::Domain(domain) => {
            let mut vec = Vec::new();
            let mut addr = domain.as_bytes().to_vec();
            vec.push(addr.len() as u8);
            vec.append(&mut addr);
            vec
        }
    }
}