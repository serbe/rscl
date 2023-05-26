use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use url::Url;

use crate::socks4::Socks4Stream;
use crate::socks5::Socks5Stream;
use crate::Error;

pub enum Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Socks5(Socks5Stream<S>),
    Socks4(Socks4Stream<S>),
}

pub struct SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub client: Client<S>,
}

impl SocksClient<TcpStream> {
    pub async fn connect(proxy: &str, target: &str) -> Result<SocksClient<TcpStream>, Error> {
        let proxy = proxy.parse::<Url>()?;
        let client = match proxy.scheme() {
            "socks5" => Ok(Client::Socks4(
                Socks4Stream::new(proxy, target.parse()?).await?,
            )),
            "socks5" => Ok(Client::Socks5(
                Socks5Stream::new(proxy, target.parse()?).await?,
            )),
            s => Err(Error::UnsupportedScheme(s.to_string())),
        }?;
        let mut socks_client = SocksClient { client };
        client.handshake().await?;
        Ok(client)
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
        let mut client = Socks5Stream::new(proxy, target.parse()?).await?;
        client.handshake().await?;
        Ok(client)
    }
}
