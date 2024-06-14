use std::{
    convert::{From, TryFrom},
    net::SocketAddr,
    pin::Pin,
    task::Poll,
};

use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::{consts, Error};

#[derive(Debug)]
pub struct Config {
    pub target: Url,
    pub cmd: Command,
}

pub struct Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub stream: S,
    pub config: Config,
}

impl<S> Socks4Stream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn from_stream(stream: S, config: Config) -> Result<Socks4Stream<S>, Error> {
        Ok(Socks4Stream { stream, config })
    }

    pub async fn handshake(&mut self) -> Result<(), Error> {
        self.init_request().await?;
        self.init_response().await?;
        Ok(())
    }

    pub async fn init_request(&mut self) -> Result<(), Error> {
        InitRequest::new(&self.config.target, &self.config.cmd)?
            .send(&mut self.stream)
            .await
    }

    pub async fn init_response(&mut self) -> Result<ServerBound, Error> {
        let init_response = InitResponse::read(&mut self.stream).await?;
        init_response.check()?;
        ServerBound::read(&mut self.stream).await
    }
}

impl Socks4Stream<TcpStream> {
    pub async fn new(proxy: Url, target: Url) -> Result<Socks4Stream<TcpStream>, Error> {
        let config = Config {
            target,
            cmd: Command::TcpConnection,
        };
        debug!("Socks4Stream::new config: {:?}", &config);
        let socket_addr = proxy
            .socket_addrs(|| None)?
            .pop()
            .ok_or(Error::SocketAddr)?;
        let stream = TcpStream::connect(socket_addr).await?;
        Socks4Stream::from_stream(stream, config)
    }

    pub async fn connect(proxy: &str, target: &str) -> Result<Socks4Stream<TcpStream>, Error> {
        debug!(
            "Socks4Stream::connect proxy: {}, target: {}",
            &proxy, target
        );
        let mut socks_stream = Socks4Stream::new(proxy.try_into()?, target.try_into()?).await?;
        socks_stream.handshake().await?;
        Ok(socks_stream)
    }
}

impl<S> AsyncRead for Socks4Stream<S>
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

impl<S> AsyncWrite for Socks4Stream<S>
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
}

impl From<Command> for u8 {
    fn from(command: Command) -> u8 {
        match command {
            Command::TcpConnection => consts::SOCKS4_COMMAND_TCP_CONNECT,
            Command::TcpBinding => consts::SOCKS4_COMMAND_TCP_BIND,
        }
    }
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            consts::SOCKS4_COMMAND_TCP_CONNECT => Ok(Command::TcpConnection),
            consts::SOCKS4_COMMAND_TCP_BIND => Ok(Command::TcpBinding),
            v => Err(Error::CommandUnknown(v)),
        }
    }
}

/// Client auth request
///
/// CONNECT
///
/// The client connects to the SOCKS server and sends a CONNECT request when
/// it wants to establish a connection to an application server. The client
/// includes in the request packet the IP address and the port number of the
/// destination host, and userid, in the following format.
///
/// +-----+-----+---------+-------+--------+------+
/// | VER | CMD | DSTPORT | DSTIP |   ID   | NULL |
/// +-----+-----+---------+-------+--------+------+
/// |  1     1       2        4    variable   1
/// # of bytes:       
/// VN is the SOCKS version number, 0x04 for this version
/// CD is the SOCKS command code and should be 1 for CONNECT request
/// ID is the user ID string, variable length, null-terminated.
/// NULL is a byte all zero bits.
#[derive(Clone, Debug)]
struct InitRequest {
    ver: u8,
    cmd: u8,
    dstport: [u8; 2],
    dstip: [u8; 4],
    id: Vec<u8>,
    term: u8,
}

impl InitRequest {
    fn new(target: &Url, cmd: &Command) -> Result<Self, Error> {
        let addr = target
            .socket_addrs(|| None)?
            .pop()
            .ok_or(Error::SocketAddr)?;
        match addr {
            SocketAddr::V4(addr) => {
                let dstip = addr.ip().octets();
                let dstport = addr.port().to_be_bytes();
                debug!(
                    "InitRequest::new ver: {}, cmd: {:?}, dstport: {:?}, dstip: {:?}, id: [], term: {}",
                    consts::SOCKS4_VERSION,
                    &cmd,
                    &dstport,
                    &dstip,
                    consts::NULL_TERMINATED
                );
                Ok(InitRequest {
                    ver: consts::SOCKS4_VERSION,
                    cmd: (*cmd).into(),
                    dstport,
                    dstip,
                    id: Vec::new(),
                    term: consts::NULL_TERMINATED,
                })
            }
            _ => Err(Error::NoIpV4Address),
        }
    }

    // fn set_command(&mut self, command: Command) {
    //     self.cmd = command.into();
    // }

    fn to_vec(&self) -> Vec<u8> {
        let mut buf = vec![self.ver, self.cmd];
        buf.append(&mut self.dstport.to_vec());
        buf.append(&mut self.dstip.to_vec());
        buf.append(&mut self.id.clone());
        buf.push(self.term);
        buf.to_vec()
    }

    // Send init request to server
    async fn send<W: AsyncWrite + Unpin>(&self, mut writer: W) -> Result<(), Error> {
        let buf = self.to_vec();
        debug!("InitRequest::send buf: {:?}", &buf);
        writer.write_all(&buf).await?;
        Ok(())
    }
}

/// Response packet from server
///             VER     REP     DSTPORT     DSTIP
/// Byte Count   1       1         2          4
#[derive(Clone, Debug)]
struct InitResponse {
    ver: u8,
    rep: u8,
}

impl InitResponse {
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<InitResponse, Error> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        let ver = buf[0];
        let rep = buf[1];
        debug!("InitResponse:read ver: {}, rep: {}", ver, rep);
        Ok(InitResponse { ver, rep })
    }

    fn check(&self) -> Result<(), Error> {
        if self.ver != consts::NULL_TERMINATED {
            Err(Error::NotSupportedSocksVersion(self.ver))
        } else {
            match self.rep {
                consts::SOCKS4_REQUEST_GRANTED => Ok(()),
                consts::SOCKS4_REQUEST_REJECTED_FAILED => Err(Error::RequestReject),
                consts::SOCKS4_REQUEST_FAILED_NOT_RUNNING_IDENTD => Err(Error::RequestFailedIdentd),
                consts::SOCKS4_REQUEST_FAILED_NOT_CONFIRM_USERID => Err(Error::RequestFailedUserID),
                _ => Err(Error::RequestWrong),
            }
        }
    }
}

pub struct ServerBound {
    pub dstip: [u8; 4],
    pub dstport: [u8; 2],
}

impl ServerBound {
    async fn read<R: AsyncRead + Unpin>(mut reader: R) -> Result<Self, Error> {
        let mut buf = [0u8; 6];
        reader.read_exact(&mut buf).await?;
        let dstport = [buf[0], buf[1]];
        let dstip = [buf[2], buf[3], buf[4], buf[5]];
        debug!(
            "ServerBound:read dstip: {:?}, dstport: {:?}",
            dstip, dstport
        );
        Ok(ServerBound { dstip, dstport })
    }
}
