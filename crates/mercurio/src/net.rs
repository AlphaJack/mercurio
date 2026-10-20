//! What both transports share for socket-based services (SMTP, IRC, MQTT, ...): the rustls client config and a line reader.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};
use crate::transport::AsyncConn;

/// Root certificates from the PEM bundle named by `SSL_CERT_FILE` (or `REQUESTS_CA_BUNDLE`), read once: both transports build their clients from it, so a changed bundle takes a restart. The bundle replaces the Mozilla roots; `None` when neither is set or the file has no usable certificate.
pub(crate) fn ca_bundle() -> Option<&'static [CertificateDer<'static>]> {
    static BUNDLE: OnceLock<Option<Vec<CertificateDer<'static>>>> = OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            let (var, path) = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]
                .into_iter()
                .find_map(|var| std::env::var_os(var).filter(|p| !p.is_empty()).map(|p| (var, p)))?;
            let certs: Vec<_> = match CertificateDer::pem_file_iter(&path) {
                Ok(it) => it.filter_map(std::result::Result::ok).collect(),
                Err(e) => {
                    log::warn!("{var}: cannot read {}: {e}; using the bundled roots", path.to_string_lossy());
                    return None;
                }
            };
            if certs.is_empty() {
                log::warn!("{var}: no certificate in {}; using the bundled roots", path.to_string_lossy());
                return None;
            }
            Some(certs)
        })
        .as_deref()
}

/// `host` as a TLS server name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| Error::transport(format!("invalid TLS server name {host}: {e}")))
}

/// Client TLS config: Mozilla roots (or [`ca_bundle`]); no verification when asked.
pub fn tls_config(verify: bool) -> std::result::Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    let config = if verify {
        let mut roots = RootCertStore::empty();
        match ca_bundle() {
            Some(certs) => {
                roots.add_parsable_certificates(certs.iter().cloned());
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    };
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Bytes asked for in one read of a socket.
pub(crate) const READ_CHUNK: usize = 4096;

/// Line-oriented helpers shared by text protocols (SMTP, IRC, ...).
pub struct LineConn<'a> {
    conn: &'a mut dyn AsyncConn,
    buf: Vec<u8>,
}

impl<'a> LineConn<'a> {
    pub fn new(conn: &'a mut dyn AsyncConn) -> Self {
        Self { conn, buf: Vec::new() }
    }

    /// Read one line without its trailing `\r\n`.
    pub async fn read_line(&mut self) -> Result<String> {
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(String::from_utf8_lossy(&line).into_owned());
            }
            let mut chunk = [0u8; READ_CHUNK];
            let n = self.conn.read(&mut chunk).await.map_err(Error::unconfirmed)?;
            if n == 0 {
                return Err(Error::unconfirmed("connection closed"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Write `line` followed by `\r\n`.
    pub async fn write_line(&mut self, line: &str) -> Result<()> {
        self.conn.write_all(line.as_bytes()).await.map_err(Error::unconfirmed)?;
        self.conn.write_all(b"\r\n").await.map_err(Error::unconfirmed)?;
        self.conn.flush().await.map_err(Error::unconfirmed)
    }

    pub async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.conn.write_all(data).await.map_err(Error::unconfirmed)?;
        self.conn.flush().await.map_err(Error::unconfirmed)
    }

    /// Upgrade to TLS; buffered plaintext is discarded (it must be empty per RFC 3207).
    pub async fn start_tls(&mut self) -> Result<()> {
        self.buf.clear();
        self.conn.start_tls().await
    }
}

impl std::fmt::Debug for LineConn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineConn").field("buffered", &self.buf.len()).finish()
    }
}
