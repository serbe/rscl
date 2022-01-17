#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("uri error {0}")]
    UriError(#[from] uri::Error),
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
}
