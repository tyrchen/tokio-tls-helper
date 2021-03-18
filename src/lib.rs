mod client_config;
mod connected;
mod error;
mod identity;
mod io;
mod server_config;
mod tls;

use std::{pin::Pin, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::ClientConfig;

pub use client_config::ClientTlsConfig;
pub use error::Error;
pub use identity::{Certificate, Identity};
pub use server_config::ServerTlsConfig;

pub(crate) use connected::Connected;

#[derive(Clone)]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
    domain: Arc<String>,
}
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<tokio_rustls::rustls::ServerConfig>,
}

pub trait Io: AsyncRead + AsyncWrite + Send + 'static {}
pub struct BoxedIo(Pin<Box<dyn Io>>);
pub trait ConnectedIo: Io + Connected {}
pub struct ServerIo(Pin<Box<dyn ConnectedIo>>);

#[cfg(test)]
mod tests {
    use http::Uri;
    use lazy_static::lazy_static;
    use std::sync::Once;
    use tokio::{
        io::{split, AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use tracing::{error, info};

    use super::*;

    lazy_static! {
        static ref INIT: Once = Once::new();
    }

    #[tokio::test]
    async fn tls_server_build_config_should_work() {
        start_logger();

        let msg = b"Hello world\n";
        let mut buf = [0; 12];

        let cert = include_str!("fixtures/server.cert");
        let key = include_str!("fixtures/server.key");
        let identity = Identity::from_pem(cert, key);
        let config = ServerTlsConfig::new().identity(identity);
        start_server(config, "0.0.0.0:5000").await;

        let cert = Certificate::from_pem(include_str!("fixtures/ca.cert"));
        let config = ClientTlsConfig::new().ca_certificate(cert);
        start_client(config, "127.0.0.1:5000", msg, &mut buf).await;
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn tls_server_load_config_file_should_work() {
        start_logger();

        let msg = b"Hello world\n";
        let mut buf = [0; 12];

        let config = toml::from_str(include_str!("fixtures/server.toml")).unwrap();
        start_server(config, "0.0.0.0:5001").await;

        let config = toml::from_str(include_str!("fixtures/client.toml")).unwrap();
        start_client(config, "127.0.0.1:5001", msg, &mut buf).await;
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn tls_server_verify_client_cert_should_work() {
        start_logger();

        let msg = b"Hello world\n";
        let mut buf = [0; 12];

        let config =
            toml::from_str(include_str!("fixtures/server_verify_client_cert.toml")).unwrap();
        start_server(config, "0.0.0.0:5002").await;

        let config = toml::from_str(include_str!("fixtures/client_with_cert.toml")).unwrap();
        start_client(config, "127.0.0.1:5002", msg, &mut buf).await;
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn tls_server_invalid_client_cert_should_fail() {
        start_logger();

        let msg = b"Hello world\n";
        let mut buf = [0; 12];

        let config: ServerTlsConfig =
            toml::from_str(include_str!("fixtures/server_verify_client_cert.toml")).unwrap();
        let acceptor = config.tls_acceptor().unwrap();
        let listener = TcpListener::bind("0.0.0.0:5003").await.unwrap();
        tokio::spawn(async move {
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            let result = acceptor.accept(stream).await;
            assert!(result.is_err());
            error!("server: failed client auth");
        });

        let config: ClientTlsConfig =
            toml::from_str(include_str!("fixtures/client_with_invalid_cert.toml")).unwrap();
        let connector = config.tls_connector(Uri::from_static("localhost")).unwrap();

        let stream = TcpStream::connect("127.0.0.1:5003").await.unwrap();
        let mut stream = connector.connect(stream).await.unwrap();
        info!("client: TLS conn established");

        stream.write_all(msg).await.unwrap();

        info!("client: send data");

        let (mut reader, _writer) = split(stream);

        let result = reader.read_exact(&mut buf).await;
        assert!(result.is_err());
    }

    async fn start_server(config: ServerTlsConfig, addr: &str) {
        let acceptor = config.tls_acceptor().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let (stream, _peer_addr) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            info!("server: Accepted client conn with TLS");

            let (mut reader, mut writer) = split(stream);
            let mut buf = [0; 12];
            reader.read_exact(&mut buf).await.unwrap();
            info!("server: got data: {:?}", buf);
            writer.write_all(&buf).await.unwrap();
            info!("server: flush the data out");
        });
    }

    async fn start_client(config: ClientTlsConfig, addr: &str, msg: &[u8], buf: &mut [u8]) {
        let connector = config.tls_connector(Uri::from_static("localhost")).unwrap();

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut stream = connector.connect(stream).await.unwrap();
        info!("client: TLS conn established");

        stream.write_all(msg).await.unwrap();

        info!("client: send data");

        let (mut reader, _writer) = split(stream);

        reader.read_exact(buf).await.unwrap();

        info!("client: read echoed data");
    }

    fn start_logger() {
        INIT.call_once(|| {
            // install global collector configured based on RUST_LOG env var.
            tracing_subscriber::fmt::init();
        });
    }
}
