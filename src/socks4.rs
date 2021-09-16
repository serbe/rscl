use std::{
    convert::{From, TryFrom},
    net::SocketAddr,
    u8,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uri::{IntoUri, Uri};

use crate::{consts, Error};

#[derive(Clone, Copy, PartialEq)]
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
/// 		        +-----+-----+---------+-------+--------+------+
/// 		        | VER | CMD | DSTPORT | DSTIP |   ID   | NULL |
/// 		        +-----+-----+---------+-------+--------+------+
///  # of bytes:	   1     1       2        4    variable   1
///
/// VN is the SOCKS version number, 0x04 for this version
/// CD is the SOCKS command code and should be 1 for CONNECT request
/// ID is the user ID string, variable length, null-terminated.
/// NULL is a byte all zero bits.
#[derive(Clone, Debug)]
struct InitRequest {
    pub ver: u8,
    pub cmd: u8,
    pub dstport: [u8; 2],
    pub dstip: [u8; 4],
    pub id: Vec<u8>,
    pub term: u8,
}

impl InitRequest {
    fn new(target: &Uri) -> Result<Self, Error> {
        let addr = target.socket_addr()?;
        match addr {
            SocketAddr::V4(addr) => {
                let dstip = addr.ip().octets();
                let dstport = addr.port().to_be_bytes();
                Ok(InitRequest {
                    ver: consts::SOCKS4_VERSION,
                    cmd: Command::TcpConnection.into(),
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
    async fn send(&self, stream: &mut TcpStream) -> Result<(), Error> {
        let buf = self.to_vec();
        stream.write_all(&buf).await?;
        Ok(())
    }
}

/// Response packet from server
/// 	        VER 	REP 	DSTPORT 	DSTIP
/// Byte Count 	1 	    1 	    2 	        4
#[derive(Clone, Debug)]
struct InitResponse {
    ver: u8,
    rep: u8,
    pub dstport: [u8; 2],
    pub dstip: [u8; 4],
}

impl InitResponse {
    async fn read(stream: &mut TcpStream) -> Result<Self, Error> {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await?;
        let ver = buf[0];
        let rep = buf[1];
        let dstport = [buf[2], buf[3]];
        let dstip = [buf[4], buf[5], buf[6], buf[7]];
        if ver != consts::NULL_TERMINATED {
            Err(Error::NotSupportedSocksVersion(ver))
        } else {
            match rep {
                consts::SOCKS4_REQUEST_GRANTED => Ok(InitResponse {
                    ver,
                    rep,
                    dstport,
                    dstip,
                }),
                consts::SOCKS4_REQUEST_REJECTED_FAILED => Err(Error::RequestReject),
                consts::SOCKS4_REQUEST_FAILED_NOT_RUNNING_IDENTD => Err(Error::RequestFailedIdentd),
                consts::SOCKS4_REQUEST_FAILED_NOT_CONFIRM_USERID => Err(Error::RequestFailedUserID),
                _ => Err(Error::RequestWrong),
            }
        }
    }
}

pub async fn connect<P: IntoUri, T: IntoUri>(proxy: P, target: T) -> Result<TcpStream, Error> {
    let proxy = &proxy.into_uri()?;
    let target = &target.into_uri()?;
    let socket_addr = proxy.socket_addr()?;
    let mut stream = TcpStream::connect(socket_addr).await?;

    InitRequest::new(target)?.send(&mut stream).await?;
    InitResponse::read(&mut stream).await?;

    Ok(stream)
}
