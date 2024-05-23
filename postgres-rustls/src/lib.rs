//! TLS support for `tokio-postgres` and `postgres` via `rustls`.
//!
//! # Examples
//!
//! ```no_run
//! use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
//! use std::fs;
//! use std::sync::Arc;
//! # #[cfg(feature = "runtime")]
//! use postgres_rustls::MakeTlsConnector;
//! use rustls_pemfile::read_one;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "runtime")] {
//! let cert = fs::read("database_cert.pem")?;
//! let cert = read_one(&mut BufReader::new(&cert))?;
//! let Some(Item::X509Certificate(cert)) = cert else {
//!    return Err("invalid certificate")?;
//! }
//! let mut root_store = RootCertStore::empty();
//! root_store.add(cert)?;
//!
//! let config = ClientConfig::builder()
//! .with_root_certificates(root_store)
//! .with_no_client_auth();
//!
//! let connector = MakeTlsConnector::new(config);
//!
//! let connect_future = tokio_postgres::connect(
//!     "host=localhost user=postgres sslmode=require",
//!     connector,
//! );
//! # }
//!
//! // ...
//! # Ok(())
//! # }
//! ```
//!
//! ```no_run
//! use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};
//! use std::fs;
//! use std::sync::Arc;
//! # #[cfg(feature = "runtime")]
//! use postgres_rustls::MakeTlsConnector;
//! use rustls_pemfile::{read_one, Item};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # #[cfg(feature = "runtime")] {
//! let cert = fs::read("database_cert.pem")?;
//! let cert = read_one(&mut BufReader::new(&cert))?;
//! let Some(Item::X509Certificate(cert)) = cert else {
//!    return Err("invalid certificate")?;
//! }
//! let mut root_store = RootCertStore::empty();
//! root_store.add(cert)?;
//!
//! let config = ClientConfig::builder()
//! .with_root_certificates(root_store)
//! .with_no_client_auth();
//!
//! let connector = MakeTlsConnector::new(config);
//!
//! let connect_future = postgres::Client::connect(
//!     "host=localhost user=postgres sslmode=require",
//!     connector,
//! );
//! # }
//!
//! // ...
//! # Ok(())
//! # }
//! ```
#![warn(rust_2018_idioms, clippy::all, missing_docs)]
use std::{
    convert::TryFrom,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use DigestAlgorithm::{Sha1, Sha256, Sha384, Sha512};

use ring::digest;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect};
use tokio_rustls::{client::TlsStream as RustlsStream, TlsConnector as RustlsConnector};
use x509_certificate::{DigestAlgorithm, SignatureAlgorithm, X509Certificate};
use SignatureAlgorithm::{
    EcdsaSha256, EcdsaSha384, Ed25519, NoSignature, RsaSha1, RsaSha256, RsaSha384, RsaSha512,
};

#[cfg(test)]
mod test;

/// A `MakeTlsConnect` implementation using the `rustls` crate.
///
/// Requires the `runtime` Cargo feature (enabled by default).
#[derive(Clone)]
#[cfg(feature = "runtime")]
pub struct MakeTlsConnector {
    config: Arc<ClientConfig>,
}

#[cfg(feature = "runtime")]
impl MakeTlsConnector {
    /// Creates a new connector.
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[cfg(feature = "runtime")]
impl<S> MakeTlsConnect<S> for MakeTlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<S>;
    type TlsConnect = TlsConnector;
    type Error = rustls::pki_types::InvalidDnsNameError;

    fn make_tls_connect(&mut self, hostname: &str) -> Result<TlsConnector, Self::Error> {
        ServerName::try_from(hostname).map(|dns_name| TlsConnector {
            hostname: dns_name.to_owned(),
            connector: Arc::clone(&self.config).into(),
        })
    }
}

/// A `TlsConnect` implementation using the `rustls` crate.
pub struct TlsConnector {
    hostname: ServerName<'static>,
    connector: RustlsConnector,
}

impl TlsConnector {
    /// Creates a new connector configured to connect to the specified domain.
    pub fn new(
        config: ClientConfig,
        domain: &str,
    ) -> Result<Self, rustls::pki_types::InvalidDnsNameError> {
        ServerName::try_from(domain).map(|hostname| Self {
            hostname: hostname.to_owned(),
            connector: RustlsConnector::from(Arc::new(config)),
        })
    }
}

impl<S> TlsConnect<S> for TlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = TlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            self.connector
                .connect(self.hostname, stream)
                .await
                .map(|s| TlsStream(Box::pin(s)))
        })
    }
}

/// The stream returned by `TlsConnector`.
pub struct TlsStream<S>(Pin<Box<RustlsStream<S>>>);

impl<S> tokio_postgres::tls::TlsStream for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        let (_, session) = self.0.get_ref();
        match session.peer_certificates() {
            Some(certs) if !certs.is_empty() => X509Certificate::from_der(&certs[0])
                .ok()
                .and_then(|cert| cert.signature_algorithm())
                .map(|algorithm| match algorithm {
                    // Note: SHA1 is upgraded to SHA256 as per https://datatracker.ietf.org/doc/html/rfc5929#section-4.1
                    RsaSha1 | RsaSha256 | EcdsaSha256 => &digest::SHA256,
                    RsaSha384 | EcdsaSha384 => &digest::SHA384,
                    RsaSha512 => &digest::SHA512,
                    Ed25519 => &digest::SHA512,
                    NoSignature(algo) => match algo {
                        Sha1 | Sha256 => &digest::SHA256,
                        Sha384 => &digest::SHA384,
                        Sha512 => &digest::SHA512,
                    },
                })
                .map(|algorithm| {
                    let hash = digest::digest(algorithm, certs[0].as_ref());
                    ChannelBinding::tls_server_end_point(hash.as_ref().into())
                })
                .unwrap_or(ChannelBinding::none()),
            _ => ChannelBinding::none(),
        }
    }
}

impl<S> AsyncRead for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        self.0.as_mut().poll_shutdown(cx)
    }
}
