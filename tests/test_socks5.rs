use std::time::Duration;

use env_logger::Env;
use rscl::{
    socks5::{AuthMethod, Command, Config, SocksClient},
    Error,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

#[cfg_attr(test, macro_use)]
extern crate log;

const SIMPLE_URL: &'static str = "http://api.ipify.org";

fn init_logger() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "debug")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);
}

#[tokio::test]
async fn test_client() {
    let test_var = "TEST_SOCKS5_PROXY";
    dotenv::dotenv().ok();
    init_logger();

    let proxy = match dotenv::var(test_var) {
        Ok(it) => it,
        _ => return,
    };

    let config = Config {
        auth: vec![AuthMethod::NoAuth],
        proxy: proxy.parse().unwrap(),
        target: SIMPLE_URL.parse().unwrap(),
        cmd: Command::TcpConnection,
        timeout: None,
    };

    let socket_addr = config
        .proxy
        .socket_addrs(|| None)
        .unwrap()
        .pop()
        .ok_or(Error::SocketAddr)
        .unwrap();

    let stream = if let Some(time) = config.timeout {
        let timeout = timeout(Duration::from_secs(time), TcpStream::connect(socket_addr)).await;
        match timeout {
            Ok(fut) => Ok(fut.unwrap()),
            Err(_) => Err(Error::NoSetTimeout),
        }
    } else {
        Ok(TcpStream::connect(socket_addr).await.unwrap())
    }
    .unwrap();
    let mut client = SocksClient { stream, config };
    client.init_request().await.unwrap();
    client.auth_response().await.unwrap();
    client.socks_request().await.unwrap();
    client.socks_replies().await.unwrap();

    client
        .stream
        .write_all(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
        .await
        .unwrap();
    client.stream.flush().await.unwrap();
    let mut buf = Vec::new();
    client.stream.read_to_end(&mut buf).await.unwrap();
    let body = String::from_utf8(buf).unwrap();
    debug!("body {}", body);
    // Ok(client)
}

// let server = MockServer::start_async().await;
// let mock = server
//     .mock_async(|when, then| {
//         when.method(GET).path(&path);
//         then.status(200)
//             .header("content-type", "text/html; charset=UTF-8")
//             .body(test_var);
//     })
//     .await;
// let mut client = Client::builder()
//     .get(&server.url(&path))
//     .proxy(&proxy)
//     .build()
//     .await
//     .unwrap();
// let response = client.send().await.unwrap();
// assert!(response.status_code().is_success());
// assert_eq!(&response.text().unwrap(), test_var);
// mock.assert();
