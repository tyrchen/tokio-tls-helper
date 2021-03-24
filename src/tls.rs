use std::{fmt, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{instrument, Instrument};

use tokio_rustls::{
    rustls::{ClientConfig, NoClientAuth, ServerConfig},
    webpki::DNSNameRef,
    TlsAcceptor as RustlsAcceptor, TlsConnector as RustlsConnector,
};

use crate::{
    Certificate, Connected, Error, Identity, TlsAcceptor, TlsClientStream, TlsConnector,
    TlsServerStream,
};

/// h2 alpn in plain format for rustls.
const ALPN_H2: &str = "h2";

#[derive(Debug, Clone)]
pub(crate) struct Cert {
    pub(crate) ca: Vec<u8>,
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) domain: String,
}

impl TlsConnector {
    #[instrument]
    pub(crate) fn new_with_rustls_cert(
        ca_cert: Option<Certificate>,
        identity: Option<Identity>,
        domain: String,
    ) -> Result<Self, Error> {
        let mut config = ClientConfig::new();
        config.set_protocols(&[Vec::from(&ALPN_H2[..])]);

        if let Some(identity) = identity {
            let (client_cert, client_key) = rustls_keys::load_identity(identity)?;
            config.set_single_client_cert(client_cert, client_key)?;
        }

        #[cfg(feature = "tls-roots")]
        {
            config.root_store = match rustls_native_certs::load_native_certs() {
                Ok(store) | Err((Some(store), _)) => store,
                Err((None, error)) => return Err(error.into()),
            };
        }

        if let Some(cert) = ca_cert {
            let mut buf = std::io::Cursor::new(&cert.pem[..]);
            config.root_store.add_pem_file(&mut buf).unwrap();
        }

        Ok(Self {
            config: Arc::new(config),
            domain: Arc::new(domain),
        })
    }

    pub async fn connect<I>(&self, io: I) -> Result<TlsClientStream<I>, Error>
    where
        I: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let dns = DNSNameRef::try_from_ascii_str(self.domain.as_str())?.to_owned();

        let io = RustlsConnector::from(self.config.clone())
            .connect(dns.as_ref(), io)
            .instrument(tracing::info_span!("tls_connector"))
            .await?;

        Ok(io)
    }
}

impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish()
    }
}

impl TlsAcceptor {
    #[instrument]
    pub(crate) fn new_with_rustls_identity(
        identity: Identity,
        client_ca_root: Option<Certificate>,
    ) -> Result<Self, Error> {
        let (cert, key) = rustls_keys::load_identity(identity)?;

        let mut config = match client_ca_root {
            None => ServerConfig::new(NoClientAuth::new()),
            Some(cert) => {
                let mut cert = std::io::Cursor::new(&cert.pem[..]);

                let mut client_root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
                if client_root_cert_store.add_pem_file(&mut cert).is_err() {
                    return Err(Error::CertificateParseError);
                }

                let client_auth =
                    tokio_rustls::rustls::AllowAnyAuthenticatedClient::new(client_root_cert_store);
                ServerConfig::new(client_auth)
            }
        };
        config.set_single_cert(cert, key)?;
        config.set_protocols(&[Vec::from(&ALPN_H2[..])]);

        Ok(Self {
            inner: Arc::new(config),
        })
    }

    pub async fn accept<IO>(&self, io: IO) -> Result<TlsServerStream<IO>, Error>
    where
        IO: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static,
    {
        let acceptor = RustlsAcceptor::from(self.inner.clone());
        acceptor
            .accept(io)
            .instrument(tracing::info_span!("tls_acceptor"))
            .await
            .map_err(Into::into)
    }
}

impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

mod rustls_keys {
    use tokio_rustls::rustls::{internal::pemfile, Certificate, PrivateKey};
    use tracing::instrument;

    use crate::{Error, Identity};

    #[instrument]
    fn load_rustls_private_key(mut cursor: std::io::Cursor<&[u8]>) -> Result<PrivateKey, Error> {
        // First attempt to load the private key assuming it is PKCS8-encoded
        if let Ok(mut keys) = pemfile::pkcs8_private_keys(&mut cursor) {
            if !keys.is_empty() {
                return Ok(keys.remove(0));
            }
        }

        // If it not, try loading the private key as an RSA key
        cursor.set_position(0);
        if let Ok(mut keys) = pemfile::rsa_private_keys(&mut cursor) {
            if !keys.is_empty() {
                return Ok(keys.remove(0));
            }
        }

        // Otherwise we have a Private Key parsing problem
        Err(Error::PrivateKeyParseError)
    }

    #[instrument]
    pub(crate) fn load_identity(
        identity: Identity,
    ) -> Result<(Vec<Certificate>, PrivateKey), Error> {
        let cert = {
            let mut cert = std::io::Cursor::new(&identity.cert.pem[..]);
            match pemfile::certs(&mut cert) {
                Ok(certs) => certs,
                Err(_) => return Err(Error::CertificateParseError),
            }
        };

        let key = {
            let key = std::io::Cursor::new(&identity.key[..]);
            match load_rustls_private_key(key) {
                Ok(key) => key,
                Err(e) => {
                    return Err(e);
                }
            }
        };

        Ok((cert, key))
    }
}
