//! What both transports share for socket-based services (SMTP, IRC, MQTT, ...): the rustls client config and a line reader.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};

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
