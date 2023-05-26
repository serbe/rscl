use log::debug;
use once_cell::sync::Lazy;
use rscl::socks4::Socks4Stream;
use rscl::socks5::Socks5Stream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SIMPLE_URL: &'static str = "http://httpbin.smp.io/ip";

static IP: Lazy<String> = Lazy::new(|| crate::my_ip());

fn my_ip() -> String {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect("api.ipify.org:80").unwrap();
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        .unwrap();
    stream.flush().unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let body = String::from_utf8(buf).unwrap();
    let split: Vec<&str> = body.splitn(2, "\r\n\r\n").collect();
    split[1].to_string()
}

fn init_logger() {
    dotenv::dotenv().ok();
    let _ = env_logger::builder().try_init();
}

fn get_env(env_var: &str) -> Option<String> {
    dotenv::var(env_var).ok()
}

async fn get_socks5_stream(proxy: &str) -> Socks5Stream<TcpStream> {
    Socks5Stream::new(proxy.parse().unwrap(), SIMPLE_URL.parse().unwrap())
        .await
        .unwrap()
}

async fn get_body(socks5_stream: &mut Socks5Stream<TcpStream>) -> String {
    socks5_stream.handshake().await.unwrap();
    socks5_stream
        .write_all(b"GET /ip HTTP/1.0\r\nHost: httpbin.smp.io\r\n\r\n")
        .await
        .unwrap();
    socks5_stream.flush().await.unwrap();
    let mut buf = Vec::new();
    socks5_stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8(buf).unwrap()
}

// TEST_SOCKS4_PROXY - an environment variable containing the socks5 server address without authorization. For example:
// socks4://127.0.0.1:3128
#[tokio::test]
async fn test_socks4_stream() {
    init_logger();

    let env_var = "TEST_SOCKS4_PROXY";
    if let Some(proxy) = get_env(env_var) {
        let mut socks4_stream = Socks4Stream::connect(&proxy, SIMPLE_URL).await.unwrap();
        socks4_stream
            .write_all(b"GET /ip HTTP/1.0\r\nHost: httpbin.smp.io\r\n\r\n")
            .await
            .unwrap();
        socks4_stream.flush().await.unwrap();
        let mut buf = Vec::new();
        socks4_stream.read_to_end(&mut buf).await.unwrap();
        let body = String::from_utf8(buf).unwrap();

        debug!("test_socks4_client body: {}", body);

        assert!(body.contains(IP.as_str()));
    };
}

// TEST_SOCKS5_PROXY - an environment variable containing the socks5 server address without authorization. For example:
// socks5://127.0.0.1:3128
#[tokio::test]
async fn test_socks5_stream() {
    init_logger();

    let env_var = "TEST_SOCKS5_PROXY";
    if let Some(proxy) = get_env(env_var) {
        let mut socks5_stream = get_socks5_stream(&proxy).await;
        let body = get_body(&mut socks5_stream).await;

        debug!("test_socks_client body: {}", body);

        assert!(body.contains(IP.as_str()));
    }
}

// TEST_SOCKS5_AUTH_PROXY - an environment variable containing the socks5 server address with authorization. For example:
// socks5://username:password@127.0.0.1:3128
#[tokio::test]
async fn test_auth_socks5_stream() {
    init_logger();

    let env_var = "TEST_SOCKS5_AUTH_PROXY";

    if let Some(proxy) = get_env(env_var) {
        let mut socks5_stream = get_socks5_stream(&proxy).await;
        let body = get_body(&mut socks5_stream).await;

        debug!("test_auth_socks_client body: {}", body);

        assert!(body.contains(IP.as_str()));
    }
}

// TEST_SOCKS5_AUTH_PROXY - an environment variable containing the address of the socks5 server with erroneous authorization. For example:
// socks5://wrong_username:wrong_password@127.0.0.1:3128
#[tokio::test]
async fn test_auth_socks5_stream_err() {
    init_logger();

    let env_var = "TEST_SOCKS5_AUTH_ERR_PROXY";

    if let Some(proxy) = get_env(env_var) {
        let mut socks5_stream = get_socks5_stream(&proxy).await;

        assert!(socks5_stream.handshake().await.is_err());
    }
}
