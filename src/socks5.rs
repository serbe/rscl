use std::{
    convert::{From, TryFrom},
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    task::Poll,
    u8,
};

use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use url::{Host, Url};

use crate::{consts, Error};

#[derive(Debug)]
pub struct Config {
    pub target: Url,
    pub auth_data: AuthData,
    pub auth: Vec<AuthMethod>,
    pub cmd: Command,
}

pub struct Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub stream: S,
    pub config: Config,
}

impl<S> Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn from_stream(stream: S, config: Config) -> Result<Socks5Stream<S>, Error> {
        Ok(Socks5Stream { stream, config })
    }

    pub async fn handshake(&mut self) -> Result<(), Error> {
        self.init_request().await?;
        self.auth_response().await?;
        self.socks_request().await?;
        self.socks_replies().await?;
        Ok(())
    }

    pub async fn init_request(&mut self) -> Result<(), Error> {
        InitRequest::new(&self.config.auth)
            .send(&mut self.stream)
            .await
    }

    pub async fn auth_response(&mut self) -> Result<(), Error> {
        AuthResponse::read(&mut self.stream)
            .await?
            .check(&self.config.auth)?;
        if self.config.auth.contains(&AuthMethod::Plain) {
            let username = self.config.auth_data.username.clone();
            let password = self.config.auth_data.password.clone();
            UserPassRequest::new(&username, &password)?
                .send(&mut self.stream)
                .await?;
            UserPassResponse::read(&mut self.stream).await?.check()?;
        }
        Ok(())
    }

    pub async fn socks_request(&mut self) -> Result<(), Error> {
        SocksRequest::new(self.config.cmd, &self.config.target)?
            .send(&mut self.stream)
            .await
    }

    pub async fn socks_replies(&mut self) -> Result<ServerBound, Error> {
        SocksReplies::read(&mut self.stream)
            .await?
            .get_addr(&mut self.stream)
            .await
    }
}

impl Socks5Stream<TcpStream> {
    pub async fn new(proxy: Url, target: Url) -> Result<Socks5Stream<TcpStream>, Error> {
        let mut auth = vec![AuthMethod::NoAuth];
        let auth_data = AuthData::from(&proxy);
        if !auth_data.username.is_empty() {
            auth.push(AuthMethod::Plain)
        };
        let config = Config {
            target,
            auth_data,
            auth,
            cmd: Command::TcpConnection,
        };
        debug!("SocksClient::new config: {:?}", &config);
        let socket_addr = proxy
            .socket_addrs(|| None)?
            .pop()
            .ok_or(Error::SocketAddr)?;
        let stream = TcpStream::connect(socket_addr).await?;
        Socks5Stream::from_stream(stream, config)
    }

    pub async fn connect(proxy: &str, target: &str) -> Result<Socks5Stream<TcpStream>, Error> {
        let mut socks_stream = Socks5Stream::new(proxy.parse()?, target.parse()?).await?;
        socks_stream.handshake().await?;
        Ok(socks_stream)
    }

    pub async fn connect_plain(
        proxy: &str,
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<Socks5Stream<TcpStream>, Error> {
        let mut proxy = proxy.parse::<Url>()?;
        let password = match password.is_empty() {
            true => None,
            false => Some(password),
        };
        proxy
            .set_username(username)
            .map_err(|_| Error::BadUsername)?;
        proxy
            .set_password(password)
            .map_err(|_| Error::BadPassword)?;
        let mut socks_stream = Socks5Stream::new(proxy, target.parse()?).await?;
        socks_stream.handshake().await?;
        Ok(socks_stream)
    }
}

impl<S> AsyncRead for Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buf)
    }
}

impl<S> AsyncWrite for Socks5Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    TcpConnection,
    TcpBinding,
    UdpPort,
}

impl From<Command> for u8 {
    fn from(command: Command) -> u8 {
        match command {
            Command::TcpConnection => consts::SOCKS5_COMMAND_TCP_CONNECT,
            Command::TcpBinding => consts::SOCKS5_COMMAND_TCP_BIND,
            Command::UdpPort => consts::SOCKS5_COMMAND_UDP_ASSOCIATE,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            consts::SOCKS5_COMMAND_TCP_CONNECT => Ok(Command::TcpConnection),
            consts::SOCKS5_COMMAND_TCP_BIND => Ok(Command::TcpBinding),
            consts::SOCKS5_COMMAND_UDP_ASSOCIATE => Ok(Command::UdpPort),
            v => Err(Error::CommandUnknown(v)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthData {
    username: String,
    password: String,
}

impl TryFrom<&str> for AuthData {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Error> {
        let url = Url::parse(value)?;
        let username = url.username().to_string();
        let password = url
            .password()
            .map_or(String::new(), |pass| pass.to_string());
        Ok(AuthData { username, password })
    }
}

impl From<&Url> for AuthData {
    fn from(value: &Url) -> Self {
        let username = value.username().to_string();
        let password = value
            .password()
            .map_or(String::new(), |pass| pass.to_string());
        AuthData { username, password }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    NoAuth,
    GssApi,
    Plain,
    NoAccept,
}

impl From<AuthMethod> for u8 {
    fn from(method: AuthMethod) -> u8 {
        match method {
            AuthMethod::NoAuth => consts::SOCKS5_AUTH_NONE,
            AuthMethod::GssApi => consts::SOCKS5_AUTH_GSSAPI,
            AuthMethod::Plain => consts::SOCKS5_AUTH_USER_PASSWORD,
            AuthMethod::NoAccept => consts::SOCKS5_AUTH_NO_ACCEPT,
        }
    }
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            consts::SOCKS5_AUTH_NONE => Ok(AuthMethod::NoAuth),
            consts::SOCKS5_AUTH_GSSAPI => Ok(AuthMethod::GssApi),
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
#[derive(Clone, Debug, PartialEq)]
struct InitRequest {
    ver: u8,
    methods: Vec<AuthMethod>,
}

impl InitRequest {
    fn new(methods: &[AuthMethod]) -> Self {
        InitRequest {
            ver: consts::SOCKS5_VERSION,
            methods: methods.to_vec(),
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        debug!(
            "InitRequest::to_vec ver: {}, nmethods: {}, methods: {:?}",
            &self.ver,
            &self.methods.len(),
            &self.methods
        );
        let mut buf = vec![self.ver, self.methods.len() as u8];
        for method in &self.methods {
            buf.push((*method).into());
        }

        buf
    }

    // Send auth request to server
    async fn send<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<(), Error> {
        let buf = self.to_vec();
        debug!("InitRequest::send buf: {:?}", &buf);
        writer.write_all(&buf).await?;
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
#[derive(Clone, Debug, PartialEq)]
struct AuthResponse {
    ver: u8,
    method: AuthMethod,
}

impl AuthResponse {
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self, Error> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        let ver = buf[0];
        let method = AuthMethod::try_from(buf[1])?;
        debug!("AuthResponse::read ver: {}, methods: {:?} ", &ver, &method);
        Ok(AuthResponse { ver, method })
    }

    fn check(&self, method: &[AuthMethod]) -> Result<(), Error> {
        if self.ver != consts::SOCKS5_VERSION {
            Err(Error::NotSupportedSocksVersion(self.ver))
        } else {
            match self.method {
                AuthMethod::GssApi => Err(Error::Unimplement),
                AuthMethod::NoAccept => Err(Error::MethodNotAccept),
                auth_method if method.contains(&auth_method) => Ok(()),
                _ => Err(Error::MethodWrong),
            }
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
#[derive(Clone, Debug, PartialEq)]
struct UserPassRequest {
    ver: u8,
    ulen: usize,
    uname: Vec<u8>,
    plen: usize,
    passwd: Vec<u8>,
}

impl UserPassRequest {
    fn new(username: &str, password: &str) -> Result<UserPassRequest, Error> {
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
        debug!(
            "UserPassRequest::to_vec ver: {}, ulen: {}, uname: {:?}, passwd: {:?}",
            self.ver, self.ulen, &self.uname, &self.passwd
        );
        let mut buf = vec![self.ver, self.ulen as u8];
        buf.extend_from_slice(&self.uname);
        buf.push(self.plen as u8);
        buf.extend_from_slice(&self.passwd);
        buf
    }

    async fn send<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<(), Error> {
        let buf = self.to_vec();
        debug!("UserPassRequest::send buf: {:?}", &buf);
        writer.write_all(&buf).await?;
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
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self, Error> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        debug!(
            "UserPassResponse::read ver: {}, status: {}",
            &buf[0], &buf[1]
        );
        Ok(UserPassResponse {
            ver: buf[0],
            status: buf[1],
        })
    }

    fn check(&self) -> Result<(), Error> {
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
    fn new(command: Command, url: &Url) -> Result<SocksRequest, Error> {
        let dst_addr = url.host().ok_or(Error::ParseHost)?.to_owned();
        let dst_port = url.port_or_known_default().ok_or(Error::ParsePort)?;
        Ok(SocksRequest {
            ver: consts::SOCKS5_VERSION,
            cmd: command,
            rsv: 0u8,
            dst_addr,
            dst_port,
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        debug!(
            "SocksRequest::to_vec ver: {}, cmd: {:?}, rsv: {}, host_addr_type: {}, dst_addr: {}, dst_port: {}",
            &self.ver, &self.cmd, &self.rsv, &self.host_addr_type(), &self.dst_addr, &self.dst_port
        );
        let mut buf = vec![self.ver, self.cmd.into(), self.rsv, self.host_addr_type()];
        for byte in self.host_to_vec() {
            buf.push(byte);
        }
        buf.push(((self.dst_port >> 8) & 0xff) as u8);
        buf.push((self.dst_port & 0xff) as u8);
        buf
    }

    fn host_addr_type(&self) -> u8 {
        match &self.dst_addr {
            Host::Domain(_) => consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME,
            Host::Ipv4(_) => consts::SOCKS5_ADDRESS_TYPE_IPV4,
            Host::Ipv6(_) => consts::SOCKS5_ADDRESS_TYPE_IPV6,
        }
    }

    fn host_to_vec(&self) -> Vec<u8> {
        match &self.dst_addr {
            Host::Domain(domain) => {
                let mut vec = Vec::new();
                let mut addr = domain.as_bytes().to_vec();
                vec.push(addr.len() as u8);
                vec.append(&mut addr);
                vec
            }
            Host::Ipv4(ipv4) => ipv4.octets().to_vec(),
            Host::Ipv6(ipv6) => ipv6.octets().to_vec(),
        }
    }

    async fn send<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<(), Error> {
        let buf = self.to_vec();
        debug!("SocksRequest::send buf: {:?}", &buf);
        writer.write_all(&buf).await?;
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
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self, Error> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).await?;
        debug!(
            "SocksReplies::read ver: {}, rep: {}, rsv: {}, atyp: {}",
            &buf[0], &buf[1], &buf[2], &buf[3]
        );
        Ok(SocksReplies {
            ver: buf[0],
            rep: buf[1],
            rsv: buf[2],
            atyp: buf[3],
        })
    }

    async fn get_addr<R: AsyncRead + Unpin>(&self, mut reader: R) -> Result<ServerBound, Error> {
        if self.ver != consts::SOCKS5_VERSION {
            return Err(Error::NotSupportedSocksVersion(self.ver));
        }
        check_reply(self.rep)?;
        if self.rsv != 0u8 {
            return Err(Error::WrongReserved(self.rsv));
        }
        let addr = match self.atyp {
            consts::SOCKS5_ADDRESS_TYPE_IPV4 => {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf).await?;
                Ok(Host::Ipv4(Ipv4Addr::from(buf)))
            }
            consts::SOCKS5_ADDRESS_TYPE_IPV6 => {
                let mut buf = [0u8; 16];
                reader.read_exact(&mut buf).await?;
                Ok(Host::Ipv6(Ipv6Addr::from(buf)))
            }
            consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME => {
                let mut buf = [0u8];
                reader.read_exact(&mut buf).await?;
                let mut buf = Vec::with_capacity(buf[0] as usize);
                buf.resize(buf[0] as usize, 0);
                reader.read_exact(&mut buf).await?;
                let host = String::from_utf8(buf)?;
                Ok(Host::Domain(host))
            }
            u => Err(Error::AddressTypeNotSupported(u)),
        }?;
        let port = reader.read_u16().await?;
        debug!(
            "SocksReplies::get_addr ServerBound addr: {}, port: {}",
            &addr, &port
        );
        Ok(ServerBound { addr, port })
    }
}

fn check_reply(value: u8) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTION: Command = Command::TcpConnection; // 0
    const BINDING: Command = Command::TcpBinding; // 1
    const UDP: Command = Command::UdpPort; // 2
    const URL: &str = "socks5://username:password@127.0.0.1:12345";
    const NOAUTH: AuthMethod = AuthMethod::NoAuth; // 0
    const GSS: AuthMethod = AuthMethod::GssApi; // 1
    const PLAIN: AuthMethod = AuthMethod::Plain; // 2
    const NOACCEPT: AuthMethod = AuthMethod::NoAccept; // 255
    const USERNAME: &str = "username";
    const PASSWORD: &str = "password";

    #[test]
    fn from_command() {
        assert_eq!(u8::from(CONNECTION), consts::SOCKS5_COMMAND_TCP_CONNECT);
        assert_eq!(u8::from(BINDING), consts::SOCKS5_COMMAND_TCP_BIND);
        assert_eq!(u8::from(UDP), consts::SOCKS5_COMMAND_UDP_ASSOCIATE);
    }

    #[test]
    fn try_to_command() {
        assert_eq!(
            Command::try_from(consts::SOCKS5_COMMAND_TCP_CONNECT),
            Ok(CONNECTION)
        );
        assert_eq!(
            Command::try_from(consts::SOCKS5_COMMAND_TCP_BIND),
            Ok(BINDING)
        );
        assert_eq!(
            Command::try_from(consts::SOCKS5_COMMAND_UDP_ASSOCIATE),
            Ok(UDP)
        );
        assert_eq!(Command::try_from(0), Err(Error::CommandUnknown(0)));
        for x in 4u8..=255u8 {
            assert_eq!(Command::try_from(x), Err(Error::CommandUnknown(x)));
        }
    }

    #[test]
    fn to_from_command() {
        for x in 1u8..=3u8 {
            let command = Command::try_from(x).unwrap();
            assert_eq!(u8::from(command), x);
        }
    }

    #[test]
    fn auth_data() {
        let data = AuthData {
            username: USERNAME.to_string(),
            password: PASSWORD.to_string(),
        };

        assert_eq!(AuthData::try_from(URL), Ok(data.clone()));
        assert_eq!(AuthData::from(&Url::parse(URL).unwrap()), data);
    }

    #[test]
    fn from_auth_method() {
        assert_eq!(u8::from(NOAUTH), consts::SOCKS5_AUTH_NONE);
        assert_eq!(u8::from(GSS), consts::SOCKS5_AUTH_GSSAPI);
        assert_eq!(u8::from(PLAIN), consts::SOCKS5_AUTH_USER_PASSWORD);
        assert_eq!(u8::from(NOACCEPT), consts::SOCKS5_AUTH_NO_ACCEPT);
    }

    #[test]
    fn try_to_auth_method() {
        assert_eq!(AuthMethod::try_from(consts::SOCKS5_AUTH_NONE), Ok(NOAUTH));
        assert_eq!(AuthMethod::try_from(consts::SOCKS5_AUTH_GSSAPI), Ok(GSS));
        assert_eq!(
            AuthMethod::try_from(consts::SOCKS5_AUTH_USER_PASSWORD),
            Ok(PLAIN)
        );
        assert_eq!(
            AuthMethod::try_from(consts::SOCKS5_AUTH_NO_ACCEPT),
            Ok(NOACCEPT)
        );
        for x in 3u8..=254u8 {
            assert_eq!(AuthMethod::try_from(x), Err(Error::MethodUnknown(x)));
        }
    }

    #[test]
    fn to_from_auth_method() {
        for x in 1u8..=3u8 {
            let command = Command::try_from(x).unwrap();
            assert_eq!(u8::from(command), x);
        }
    }

    #[test]
    fn init_request() {
        let init_req = InitRequest::new(&[PLAIN]);
        assert_eq!(
            init_req,
            InitRequest {
                ver: consts::SOCKS5_VERSION,
                methods: vec![PLAIN]
            }
        );
        assert_eq!(
            init_req.to_vec(),
            vec![
                consts::SOCKS5_VERSION,
                1u8,
                consts::SOCKS5_AUTH_USER_PASSWORD
            ]
        );
    }

    #[test]
    fn auth_response() {
        let auth_resp = AuthResponse {
            ver: consts::SOCKS5_VERSION,
            method: PLAIN,
        };
        assert!(auth_resp.check(&[PLAIN]).is_ok());
        assert_eq!(auth_resp.check(&[GSS]), Err(Error::MethodWrong));
        assert_eq!(
            AuthResponse {
                ver: consts::SOCKS4_VERSION,
                method: PLAIN,
            }
            .check(&[PLAIN]),
            Err(Error::NotSupportedSocksVersion(consts::SOCKS4_VERSION))
        );
        assert_eq!(
            AuthResponse {
                ver: consts::SOCKS5_VERSION,
                method: NOACCEPT,
            }
            .check(&[PLAIN]),
            Err(Error::MethodNotAccept)
        );
        assert_eq!(
            AuthResponse {
                ver: consts::SOCKS5_VERSION,
                method: GSS,
            }
            .check(&[PLAIN]),
            Err(Error::Unimplement)
        );
    }

    #[test]
    fn user_pass_request() {
        let up_request = UserPassRequest::new(USERNAME, PASSWORD);
        assert_eq!(
            up_request,
            Ok(UserPassRequest {
                ver: 1u8,
                ulen: 8,
                uname: USERNAME.as_bytes().to_vec(),
                plen: 8,
                passwd: PASSWORD.as_bytes().to_vec()
            })
        );
        assert_eq!(
            UserPassRequest::new(&(0..257).map(|_| "X").collect::<String>(), PASSWORD),
            Err(Error::UnameLenOverflow(257))
        );
        assert_eq!(
            UserPassRequest::new(USERNAME, &(0..258).map(|_| "X").collect::<String>()),
            Err(Error::PasswdLenOverflow(258))
        );
        assert_eq!(
            up_request.unwrap().to_vec(),
            vec![
                1, 8, 117, 115, 101, 114, 110, 97, 109, 101, 8, 112, 97, 115, 115, 119, 111, 114,
                100
            ]
        );
    }

    #[test]
    fn user_pass_response() {
        let up_response = UserPassResponse { ver: 1, status: 0 };
        assert!(up_response.check().is_ok());
        assert_eq!(
            UserPassResponse { ver: 3, status: 1 }.check(),
            Err(Error::NotSupportedVersion(3))
        );
        assert_eq!(
            UserPassResponse { ver: 1, status: 2 }.check(),
            Err(Error::WrongStatus(2))
        );
    }
}
