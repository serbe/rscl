use log::debug;
use rscl::socks5::SocksClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SIMPLE_URL: &'static str = "http://api.ipify.org";

fn init_logger() {
    dotenv::dotenv().ok();
    let _ = env_logger::builder().try_init();
}

#[tokio::test]
async fn test_socks_client() {
    init_logger();

    let test_var = "TEST_SOCKS5_PROXY";

    let proxy = match dotenv::var(test_var) {
        Ok(it) => it,
        _ => return,
    };

    let mut client = SocksClient::new(proxy.parse().unwrap(), SIMPLE_URL.parse().unwrap())
        .await
        .unwrap();

    client.handshake().await.unwrap();

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let body = String::from_utf8(buf).unwrap();
    debug!("body {}", body);
}

#[tokio::test]
async fn test_auth_socks_client() {
    init_logger();

    let test_var = "TEST_AUTH_PROXY";

    let proxy = match dotenv::var(test_var) {
        Ok(it) => it,
        _ => return,
    };

    let mut client = SocksClient::new(proxy.parse().unwrap(), SIMPLE_URL.parse().unwrap())
        .await
        .unwrap();

    client.handshake().await.unwrap();

    client
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        .await
        .unwrap();
    client.flush().await.unwrap();
    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();
    let body = String::from_utf8(buf).unwrap();
    debug!("body {}", body);
}

#[tokio::test]
async fn test_auth_socks_err_client() {
    init_logger();

    let test_var = "TEST_ERR_AUTH_PROXY";

    let proxy = match dotenv::var(test_var) {
        Ok(it) => it,
        _ => return,
    };

    let mut client = SocksClient::new(proxy.parse().unwrap(), SIMPLE_URL.parse().unwrap())
        .await
        .unwrap();

    assert!(client.handshake().await.is_err());
}
