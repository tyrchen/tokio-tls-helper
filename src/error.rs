use thiserror::Error;

/// General error definition for the project
#[derive(Error, Debug)]
pub enum Error {
    // detailed errors
    #[error("HTTP/2 was not negotiated.")]
    H2NotNegotiated,
    #[error("Error parsing TLS certificate.")]
    CertificateParseError,
    #[error("Error parsing TLS private key - no RSA or PKCS8-encoded keys found.")]
    PrivateKeyParseError,
    #[error("transport error")]
    Transport,
    #[error("invalid URI")]
    InvalidUri,
    #[error("user agent is not a valid header value")]
    InvalidUserAgent,

    // other errors
    #[error("TLS error: {0}")]
    TLSError(#[from] tokio_rustls::rustls::TLSError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("IO error: {0}")]
    DNSError(#[from] webpki::InvalidDNSNameError),
}
