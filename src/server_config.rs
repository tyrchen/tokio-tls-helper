use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{Certificate, Error, Identity, TlsAcceptor};

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct ServerTlsConfig {
    identity: Option<Identity>,
    client_ca_root: Option<Certificate>,
}

impl fmt::Debug for ServerTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTlsConfig").finish()
    }
}

impl ServerTlsConfig {
    /// Creates a new `ServerTlsConfig`.
    pub fn new() -> Self {
        ServerTlsConfig {
            identity: None,
            client_ca_root: None,
        }
    }

    /// Sets the [`Identity`] of the server.
    pub fn identity(self, identity: Identity) -> Self {
        ServerTlsConfig {
            identity: Some(identity),
            ..self
        }
    }

    /// Sets a certificate against which to validate client TLS certificates.
    pub fn client_ca_root(self, cert: Certificate) -> Self {
        ServerTlsConfig {
            client_ca_root: Some(cert),
            ..self
        }
    }

    pub fn tls_acceptor(&self) -> Result<TlsAcceptor, Error> {
        TlsAcceptor::new_with_rustls_identity(
            self.identity.clone().unwrap(),
            self.client_ca_root.clone(),
        )
    }
}
