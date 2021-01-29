use url::{Host, Origin, Url};

use crate::consts;
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
pub struct Addr {
    pub host: Host,
    pub port: u16,
}

impl Addr {
    pub fn new(url: &Url) -> Result<Self> {
        match url.origin() {
            Origin::Opaque(_) => Err(Error::ParseAddr),
            Origin::Tuple(_, host, port) => Ok(Addr { host, port }),
        }
    }

    pub fn addr_type(&self) -> u8 {
        match self.host {
            Host::Ipv4(_) => consts::SOCKS5_ADDRESS_TYPE_IPV4,
            Host::Ipv6(_) => consts::SOCKS5_ADDRESS_TYPE_IPV6,
            Host::Domain(_) => consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self.host.clone() {
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

    pub fn host_str(&self) -> String {
        match self.host.clone() {
            Host::Ipv4(ipv4) => ipv4.to_string(),
            Host::Ipv6(ipv6) => ipv6.to_string(),
            Host::Domain(domain) => domain,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use url::Host;

    use crate::{addr::Addr, utils::parse_url};

    #[test]
    fn addr_ipv4() {
        let url = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(
            Addr::new(&url).unwrap(),
            Addr {
                host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                port: 8080
            }
        );
    }

    #[test]
    fn addr_ipv6() {
        let url = parse_url("http://[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]:129").unwrap();
        assert_eq!(
            Addr::new(&url).unwrap(),
            Addr {
                host: Host::Ipv6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0x11a3, 0x9d7, 0x1f34, 0x8a2e, 0x7a0, 0x765d
                )),
                port: 129
            }
        );
    }

    #[test]
    fn addr_domain() {
        let url = parse_url("http://test.com:123").unwrap();
        assert_eq!(
            Addr::new(&url).unwrap(),
            Addr {
                host: Host::Domain("test.com".into()),
                port: 123,
            }
        );
    }
}
