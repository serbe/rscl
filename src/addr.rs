use std::{borrow::Cow, net::SocketAddr, str::FromStr};

use crate::consts;
use crate::{Error, Result};
// use crate::utils::is_valid_ups;

#[derive(Clone, Debug, PartialEq)]
pub enum Addr<'a> {
    IP(SocketAddr),
    Domain(Cow<'a, str>, u16),
}

impl<'a> Addr<'a> {
    pub fn to_owned(&self) -> Addr<'static> {
        match self {
            Addr::IP(ip) => Addr::IP(*ip),
            Addr::Domain(host, port) => Addr::Domain(String::from(host.clone()).into(), *port),
        }
    }

    pub fn addr_type(&self) -> u8 {
        match self {
            Addr::IP(SocketAddr::V4(_)) => consts::SOCKS5_ADDRESS_TYPE_IPV4,
            Addr::IP(SocketAddr::V6(_)) => consts::SOCKS5_ADDRESS_TYPE_IPV6,
            Addr::Domain(_, _) => consts::SOCKS5_ADDRESS_TYPE_DOMAINNAME,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Addr::IP(ip) => match ip {
                SocketAddr::V4(ipv4) => ipv4.ip().octets().to_vec(),
                SocketAddr::V6(ipv6) => ipv6.ip().octets().to_vec(),
            },
            Addr::Domain(domain, _port) => {
                let mut vec = Vec::new();
                let mut addr = domain.as_bytes().to_vec();
                vec.push(addr.len() as u8);
                vec.append(&mut addr);
                vec
            }
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Addr::IP(ip) => ip.port(),
            Addr::Domain(_host, port) => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Addr::IP(ip) => ip.ip().to_string(),
            Addr::Domain(host, _port) => host.to_string(),
        }
    }
}

impl<'a> FromStr for Addr<'a> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let rsplit: Vec<String> = s.rsplitn(2, ':').map(|x| x.to_string()).collect();
        if rsplit.len() != 2 {
            return Err(Error::ParseHost);
        }
        let (host, port) = (rsplit[1].clone(), rsplit[0].clone());
        let port = port
            .parse::<u16>()
            .map_err(|_| Error::ParsePort(port.to_string()))?;

        match s.parse::<SocketAddr>() {
            Ok(socket) => Ok(Addr::IP(socket)),
            Err(_) => Ok(Addr::Domain(host.into(), port)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use crate::addr::Addr;

    #[test]
    fn addr_ipv4() {
        assert_eq!(
            "127.0.0.1:8080".parse::<Addr>().unwrap(),
            Addr::IP(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8080
            ))
        );
    }

    #[test]
    fn addr_ipv6() {
        assert_eq!(
            "[2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d]:129"
                .parse::<Addr>()
                .unwrap(),
            Addr::IP(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0x11a3, 0x9d7, 0x1f34, 0x8a2e, 0x7a0, 0x765d
                )),
                129
            ))
        );
    }

    #[test]
    fn addr_domain() {
        assert_eq!(
            "test.com:123".parse::<Addr>().unwrap(),
            Addr::Domain("test.com".into(), 123)
        );
    }

    #[test]
    fn addr_err() {
        assert!("127.0.0.1".parse::<Addr>().is_err());
        assert!("test.com".parse::<Addr>().is_err());
    }
}
