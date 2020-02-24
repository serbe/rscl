use std::{io, net, result, string};

use thiserror::Error;

pub type Result<T> = result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("uri error")]
    UriError(#[from] uri::Error),
    #[error("Socks version: {0} not supported")]
    NotSupportedSocksVersion(u8),
    #[error("Version: {0} not supported")]
    NotSupportedVersion(u8),
    #[error("io error")]
    IO(#[from] io::Error),
    #[error("string from utf8 error")]
    Utf8Error(#[from] string::FromUtf8Error),
    #[error("Net address parse")]
    StdParseAddr(#[from] net::AddrParseError),
    #[error("Unimplement feature")]
    Unimplement,
    #[error("Auth method not accepted")]
    MethodNotAccept,
    #[error("Unknown auth method: {0}")]
    MethodUnknown(u8),
    #[error("Wrong method")]
    MethodWrong,
    // #[error("Connection not allowed by ruleset")]
    // WrongRuleset,
    // #[error("Network unreachable")]
    // NetworkUnreachable,
    // #[error("Host unreachable")]
    // HostUnreachable,
    // #[error("Connection refused by destination host")]
    // ConnectionRefused,
    // #[error("TTL expired")]
    // TtlExpired,
    // #[error("Command not supported / protocol error")]
    // CommandOrProtocolError,
    // #[error("Address type not supported")]
    // WrongAddressType,
    // #[error("NstivrTls")]
    // NativeTls(#[from] native_tls::Error),
    #[error("Wrong reserved byte: {0}")]
    WrongReserved(u8),
    #[error("Address type: {0} not supported")]
    AddressTypeNotSupported(u8),
    #[error("Unknown command: {0}")]
    CommandUnknown(u8),
    #[error("Parse ip version 6")]
    ParseIPv6,
    #[error("Parse address")]
    ParseAddr,
    #[error("Parse host")]
    ParseHost,
    #[error("Parse port: {0}")]
    ParsePort(String),
    #[error("Unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("Empty scheme")]
    EmptyScheme,
    #[error("Empty authority")]
    EmptyAuthority,
    #[error("Username len more when 255: {0}")]
    UnameLenOverflow(usize),
    #[error("Password len more when 255: {0}")]
    PasswdLenOverflow(usize),
    #[error("Wrong status: {0}")]
    WrongStatus(u8),
    #[error("General SOCKS server failure")]
    ReplyGeneralFailure,
    #[error("Connection not allowed by ruleset")]
    ReplyConnectionNotAllowed,
    #[error("Network unreachable")]
    ReplyNetworkUnreachable,
    #[error("Host unreachable")]
    ReplyHostUnreachable,
    #[error("Connection refused")]
    ReplyConnectionRefused,
    #[error("TTL expired")]
    ReplyTtlExpired,
    #[error("Command not supported")]
    ReplyCommandNotSupported,
    #[error("Address type not supported")]
    ReplyAddressTypeNotSupported,
    #[error("Reply unassigned: {0}")]
    ReplyUnassigned(u8),
}

// #[fail("{}", _0)]
// Io(#[cause] std::io::Error),
// #[fail("{}", _0)]
// ParseError(#[cause] std::string::ParseError),
// #[fail("Target address is invalid: {}", _0)]
// InvalidTargetAddress(&'static str),
// #[fail("Url fragment is invalid: {}", _0)]
// ParseFragment(&'static str),
// #[fail("Url host is invalid: {}", _0)]
// ParseHost(&'static str),
// #[fail("Url IPv6 is invalid: {}", _0)]
// ParseIPv6(&'static str),
// #[fail("Url path is invalid: {}", _0)]
// ParsePath(&'static str),
// #[fail("Url port is invalid: {}", _0)]
// ParsePort(&'static str),
// #[fail("Url query is invalid: {}", _0)]
// ParseQuery(&'static str),
// #[fail("Url scheme is invalid: {}", _0)]
// ParseScheme(&'static str),
// #[fail("Url UserInfo is invalid: {}", _0)]
// ParseUserInfo(&'static str),

// impl From<std::io::Error> for Error {
//     fn from(err: std::io::Error) -> Error {
//         Error::Io(err)
//     }
// }

// impl From<String> for Error {
//     fn from(err: String) -> Error {
//         Error::Io(std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err,
//         ))
//     }
// }

// impl From<&str> for Error {
//     fn from(err: &str) -> Error {
//         Error::Io(std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err,
//         ))
//     }
// }

// impl From<Error> for std::io::Error {
//     fn from(err: Error) -> std::io::Error {
//         std::io::Error::new(
//             std::io::ErrorKind::Other,
//             err.to_string(),
//         )
//     }
// }
