use std::pin::Pin;
use std::task::Poll;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::socks4::Socks4Stream;
use crate::socks5::Socks5Stream;
use crate::utils::IntoUrl;
use crate::Error;

pub enum SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Socks5(Socks5Stream<S>),
    Socks4(Socks4Stream<S>),
}

impl<S> SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn handshake(&mut self) -> Result<(), Error> {
        match self {
            SocksClient::Socks5(client) => client.handshake().await,
            SocksClient::Socks4(client) => client.handshake().await,
        }
    }

    pub fn stream(self) -> S {
        match self {
            SocksClient::Socks5(s) => s.stream,
            SocksClient::Socks4(s) => s.stream,
        }
    }
}

impl<S> AsyncRead for SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            SocksClient::Socks5(s) => Pin::new(s).poll_read(context, buf),
            SocksClient::Socks4(s) => Pin::new(s).poll_read(context, buf),
        }
    }
}

impl<S> AsyncWrite for SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::get_mut(self) {
            SocksClient::Socks5(s) => Pin::new(s).poll_write(context, buf),
            SocksClient::Socks4(s) => Pin::new(s).poll_write(context, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            SocksClient::Socks5(s) => Pin::new(s).poll_flush(context),
            SocksClient::Socks4(s) => Pin::new(s).poll_flush(context),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            SocksClient::Socks5(s) => Pin::new(s).poll_shutdown(context),
            SocksClient::Socks4(s) => Pin::new(s).poll_shutdown(context),
        }
    }
}

impl SocksClient<TcpStream> {
    pub async fn connect<U: IntoUrl, V: IntoUrl>(
        proxy: U,
        target: V,
    ) -> Result<SocksClient<TcpStream>, Error> {
        let proxy = proxy.into_url()?;
        let mut client = match proxy.scheme() {
            "socks4" => Ok(SocksClient::Socks4(
                Socks4Stream::new(proxy, target.into_url()?).await?,
            )),
            "socks5" => Ok(SocksClient::Socks5(
                Socks5Stream::new(proxy, target.into_url()?).await?,
            )),
            s => Err(Error::UnsupportedScheme(s.to_string())),
        }?;
        client.handshake().await?;
        Ok(client)
    }

    pub async fn connect_plain<U: IntoUrl, V: IntoUrl>(
        proxy: U,
        target: V,
        username: &str,
        password: &str,
    ) -> Result<Socks5Stream<TcpStream>, Error> {
        let mut proxy = proxy.into_url()?;
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
        let mut client = Socks5Stream::new(proxy, target.into_url()?).await?;
        client.handshake().await?;
        Ok(client)
    }
}
