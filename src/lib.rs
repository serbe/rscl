pub mod consts;
pub mod error;
pub mod socks4;
pub mod socks5;

pub use error::Error;

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use tokio::{
//         io::{AsyncReadExt, AsyncWriteExt},
//         net::TcpStream,
//     };

// #[tokio::test]
// async fn conn_v5() {
//     let mut stream = socks5::connect("socks5://127.0.0.1:5959", "http://api.ipify.org")
//         .await
//         .unwrap();
//     stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
//     stream.flush().await.unwrap();
//     let mut buf = Vec::new();
//     stream.read_to_end(&mut buf).await.unwrap();
//     assert!(!buf.is_empty());
// }

// #[tokio::test]
// async fn conn_v4() {
//     let mut stream = socks4::connect("socks4://127.0.0.1:5959", "http://api.ipify.org")
//         .await
//         .unwrap();
//     stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
//     stream.flush().await.unwrap();
//     let mut buf = Vec::new();
//     stream.read_to_end(&mut buf).await.unwrap();
//     assert!(!buf.is_empty());
// }
// }
