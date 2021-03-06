use hyper::server::conn::AddrStream;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_rustls::{rustls::Session, server::TlsStream};

use crate::Certificate;

/// Trait that connected IO resources implement.
///
/// The goal for this trait is to allow users to implement
/// custom IO types that can still provide the same connection
/// metadata.
pub trait Connected {
    /// Return the remote address this IO resource is connected too.
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Return the set of connected peer TLS certificates.
    fn peer_certs(&self) -> Option<Vec<Certificate>> {
        None
    }
}

impl Connected for AddrStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr())
    }
}

impl Connected for TcpStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.peer_addr().ok()
    }
}

impl<T: Connected> Connected for TlsStream<T> {
    fn remote_addr(&self) -> Option<SocketAddr> {
        let (inner, _) = self.get_ref();

        inner.remote_addr()
    }

    fn peer_certs(&self) -> Option<Vec<Certificate>> {
        let (_, session) = self.get_ref();

        if let Some(certs) = session.get_peer_certificates() {
            let certs = certs
                .into_iter()
                .map(|c| Certificate::from_pem(c.0))
                .collect();
            Some(certs)
        } else {
            None
        }
    }
}
