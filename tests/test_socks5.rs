use log::debug;
use rscl::socks4::Socks4Client;
use rscl::socks5::SocksClient;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SIMPLE_URL: &'static str = "http://httpbin.smp.io/ip";

fn init_logger() {
    dotenv::dotenv().ok();
    let _ = env_logger::builder().try_init();
}

async fn get_client(env_var: &str) -> SocksClient<TcpStream> {
    let proxy = dotenv::var(env_var).unwrap();

    SocksClient::new(proxy.parse().unwrap(), SIMPLE_URL.parse().unwrap())
        .await
        .unwrap()
}

async fn get_body(client: &mut SocksClient<TcpStream>) -> String {
    client.handshake().await.unwrap();
    client
        .write_all(b"GET /ip HTTP/1.0\r\nHost: httpbin.smp.io\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    String::from_utf8(buf).unwrap()
}

// TEST_SOCKS4_PROXY - an environment variable containing the socks5 server address without authorization. For example:
// socks4://127.0.0.1:3128
#[tokio::test]
async fn test_socks4_client() {
    init_logger();

    let env_var = "TEST_SOCKS4_PROXY";
    let proxy = dotenv::var(env_var).unwrap();

    let mut client = Socks4Client::connect(&proxy, SIMPLE_URL).await.unwrap();
    client
        .write_all(b"GET /ip HTTP/1.0\r\nHost: httpbin.smp.io\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let body = String::from_utf8(buf).unwrap();

    debug!("test_socks4_client body: {}", body);
}

// TEST_SOCKS5_PROXY - an environment variable containing the socks5 server address without authorization. For example:
// socks5://127.0.0.1:3128
#[tokio::test]
async fn test_socks_client() {
    init_logger();

    let env_var = "TEST_SOCKS5_PROXY";

    let mut client = get_client(env_var).await;
    let body = get_body(&mut client).await;

    debug!("test_socks_client body: {}", body);
}

// TEST_SOCKS5_AUTH_PROXY - an environment variable containing the socks5 server address with authorization. For example:
// socks5://username:password@127.0.0.1:3128
#[tokio::test]
async fn test_auth_socks_client() {
    init_logger();

    let env_var = "TEST_SOCKS5_AUTH_PROXY";

    let mut client = get_client(env_var).await;
    let body = get_body(&mut client).await;

    debug!("test_auth_socks_client body: {}", body);
}

// TEST_SOCKS5_AUTH_PROXY - an environment variable containing the address of the socks5 server with erroneous authorization. For example:
// socks5://wrong_username:wrong_password@127.0.0.1:3128
#[tokio::test]
async fn test_auth_socks_err_client() {
    init_logger();

    let env_var = "TEST_SOCKS5_AUTH_ERR_PROXY";

    let mut client = get_client(env_var).await;

    assert!(client.handshake().await.is_err());
}
