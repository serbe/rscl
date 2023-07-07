use std::pin::Pin;
use std::task::Poll;

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

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn handshake(&mut self) -> Result<(), Error> {
        match self {
            Client::Socks5(client) => client.handshake().await,
            Client::Socks4(client) => client.handshake().await,
        }
    }
}

impl<S> AsyncWrite for Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::get_mut(self) {
            Client::Socks5(s) => Pin::new(s).poll_write(context, buf),
            Client::Socks4(s) => Pin::new(s).poll_write(context, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            Client::Socks5(s) => Pin::new(s).poll_flush(context),
            Client::Socks4(s) => Pin::new(s).poll_flush(context),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            Client::Socks5(s) => Pin::new(s).poll_shutdown(context),
            Client::Socks4(s) => Pin::new(s).poll_shutdown(context),
        }
    }
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
            "socks4" => Ok(Client::Socks4(
                Socks4Stream::new(proxy, target.parse()?).await?,
            )),
            "socks5" => Ok(Client::Socks5(
                Socks5Stream::new(proxy, target.parse()?).await?,
            )),
            s => Err(Error::UnsupportedScheme(s.to_string())),
        }?;
        let mut socks_client = SocksClient { client };
        socks_client.handshake().await?;
        Ok(socks_client)
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

    async fn handshake(&mut self) -> Result<(), Error> {
        self.client.handshake().await
    }
}

impl<S> AsyncRead for Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::get_mut(self) {
            Client::Socks5(s) => Pin::new(s).poll_read(context, buf),
            Client::Socks4(s) => Pin::new(s).poll_read(context, buf),
        }
    }
}

impl<S> AsyncRead for SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.client).poll_read(context, buf)
    }
}

impl<S> AsyncWrite for SocksClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.client).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.client).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.client).poll_shutdown(context)
    }
}
