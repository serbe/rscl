#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("url error")]
    UrlParseError(#[from] url::ParseError),
    #[error("Socks version: {0} not supported")]
    NotSupportedSocksVersion(u8),
    #[error("Version: {0} not supported")]
    NotSupportedVersion(u8),
    #[error("io error {0}")]
    Io(#[from] std::io::Error),
    #[error("string from utf8 error {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("Net address parse {0}")]
    StdParseAddr(#[from] std::net::AddrParseError),
    #[error("Unimplement feature")]
    Unimplement,
    #[error("Auth method not accepted")]
    MethodNotAccept,
    #[error("Unknown auth method: {0}")]
    MethodUnknown(u8),
    #[error("Wrong method")]
    MethodWrong,
    #[error("No get socket address")]
    SocketAddr,
    #[error("Wrong reserved byte: {0}")]
    WrongReserved(u8),
    #[error("Address type: {0} not supported")]
    AddressTypeNotSupported(u8),
    #[error("Unknown command: {0}")]
    CommandUnknown(u8),
    #[error("Parse ip version 6")]
    ParseIPv6,
    #[error("Parse host")]
    ParseHost,
    #[error("Parse port")]
    ParsePort,
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
    #[error("No set username for uri")]
    BadUsername,
    #[error("No set password for uri")]
    BadPassword,
    #[error("Request rejected or failed")]
    RequestReject,
    #[error("Request failed because client is not running identd (or not reachable from server)")]
    RequestFailedIdentd,
    #[error("Request failed because client's identd could not confirm the user ID in the request")]
    RequestFailedUserID,
    #[error("Wrong request")]
    RequestWrong,
    #[error("No IpV4 address")]
    NoIpV4Address,
    #[error("No set timeout to TcpStream")]
    NoSetTimeout,
    #[error("No url")]
    NoUrl,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::UrlParseError(err), Error::UrlParseError(other_err)) => {
                err.to_string() == other_err.to_string()
            }
            (
                Error::NotSupportedSocksVersion(value),
                Error::NotSupportedSocksVersion(other_value),
            ) => value == other_value,
            (Error::NotSupportedVersion(value), Error::NotSupportedVersion(other_value)) => {
                value == other_value
            }
            (Error::Io(err), Error::Io(other_err)) => err.to_string() == other_err.to_string(),
            (Error::Utf8Error(err), Error::Utf8Error(other_err)) => {
                err.to_string() == other_err.to_string()
            }
            (Error::StdParseAddr(err), Error::StdParseAddr(other_err)) => {
                err.to_string() == other_err.to_string()
            }
            (Error::Unimplement, Error::Unimplement) => true,
            (Error::MethodNotAccept, Error::MethodNotAccept) => true,
            (Error::MethodUnknown(value), Error::MethodUnknown(other_value)) => {
                value == other_value
            }
            (Error::MethodWrong, Error::MethodWrong) => true,
            (Error::SocketAddr, Error::SocketAddr) => true,
            (Error::WrongReserved(value), Error::WrongReserved(other_value)) => {
                value == other_value
            }
            (
                Error::AddressTypeNotSupported(value),
                Error::AddressTypeNotSupported(other_value),
            ) => value == other_value,
            (Error::CommandUnknown(value), Error::CommandUnknown(other_value)) => {
                value == other_value
            }
            (Error::ParseIPv6, Error::ParseIPv6) => true,
            (Error::ParseHost, Error::ParseHost) => true,
            (Error::ParsePort, Error::ParsePort) => true,
            (Error::UnsupportedScheme(value), Error::UnsupportedScheme(other_value)) => {
                value == other_value
            }
            (Error::EmptyScheme, Error::EmptyScheme) => true,
            (Error::EmptyAuthority, Error::EmptyAuthority) => true,
            (Error::UnameLenOverflow(value), Error::UnameLenOverflow(other_value)) => {
                value == other_value
            }
            (Error::PasswdLenOverflow(value), Error::PasswdLenOverflow(other_value)) => {
                value == other_value
            }
            (Error::WrongStatus(value), Error::WrongStatus(other_value)) => value == other_value,
            (Error::ReplyGeneralFailure, Error::ReplyGeneralFailure) => true,
            (Error::ReplyConnectionNotAllowed, Error::ReplyConnectionNotAllowed) => true,
            (Error::ReplyNetworkUnreachable, Error::ReplyNetworkUnreachable) => true,
            (Error::ReplyHostUnreachable, Error::ReplyHostUnreachable) => true,
            (Error::ReplyConnectionRefused, Error::ReplyConnectionRefused) => true,
            (Error::ReplyTtlExpired, Error::ReplyTtlExpired) => true,
            (Error::ReplyCommandNotSupported, Error::ReplyCommandNotSupported) => true,
            (Error::ReplyAddressTypeNotSupported, Error::ReplyAddressTypeNotSupported) => true,
            (Error::ReplyUnassigned(value), Error::ReplyUnassigned(other_value)) => {
                value == other_value
            }
            (Error::BadUsername, Error::BadUsername) => true,
            (Error::BadPassword, Error::BadPassword) => true,
            (Error::RequestReject, Error::RequestReject) => true,
            (Error::RequestFailedIdentd, Error::RequestFailedIdentd) => true,
            (Error::RequestFailedUserID, Error::RequestFailedUserID) => true,
            (Error::RequestWrong, Error::RequestWrong) => true,
            (Error::NoIpV4Address, Error::NoIpV4Address) => true,
            (Error::NoSetTimeout, Error::NoSetTimeout) => true,
            (Error::NoUrl, Error::NoUrl) => true,
            _ => false,
        }
    }
}
