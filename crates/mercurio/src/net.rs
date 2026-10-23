//! What both transports share for socket-based services (SMTP, IRC, MQTT, ...): the rustls client config and a line reader.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

use crate::error::{Error, Result};

/// Root certificates from the PEM bundle named by `SSL_CERT_FILE` (or `REQUESTS_CA_BUNDLE`), read once: both transports build their clients from it, so a changed bundle takes a restart. The bundle replaces the Mozilla roots; `None` when neither is set or the file has no usable certificate. Without the `bundle-certificates` feature, an unset variable falls back to the system bundle (`SYSTEM_BUNDLES`).
pub(crate) fn ca_bundle() -> Option<&'static [CertificateDer<'static>]> {
    static BUNDLE: OnceLock<Option<Vec<CertificateDer<'static>>>> = OnceLock::new();
    BUNDLE
        .get_or_init(|| {
            let named = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]
                .into_iter()
                .find_map(|var| std::env::var_os(var).filter(|p| !p.is_empty()).map(|p| (var, p)));
            let Some((var, path)) = named else { return system_bundle() };
            let certs: Vec<_> = match CertificateDer::pem_file_iter(&path) {
                Ok(it) => it.filter_map(std::result::Result::ok).collect(),
                Err(e) => {
                    log::warn!("{var}: cannot read {}: {e}; using the {FALLBACK} roots", path.to_string_lossy());
                    return system_bundle();
                }
            };
            if certs.is_empty() {
                log::warn!("{var}: no certificate in {}; using the {FALLBACK} roots", path.to_string_lossy());
                return system_bundle();
            }
            Some(certs)
        })
        .as_deref()
}

#[cfg(feature = "bundle-certificates")]
const FALLBACK: &str = "bundled";
#[cfg(not(feature = "bundle-certificates"))]
const FALLBACK: &str = "system";

#[cfg(feature = "bundle-certificates")]
fn system_bundle() -> Option<Vec<CertificateDer<'static>>> {
    None
}

/// Where Linux distributions keep their PEM bundle (Go's `crypto/x509` list), tried in order.
#[cfg(not(feature = "bundle-certificates"))]
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The first `SYSTEM_BUNDLES` file with a certificate; with none, every verified TLS connection fails.
#[cfg(not(feature = "bundle-certificates"))]
fn system_bundle() -> Option<Vec<CertificateDer<'static>>> {
    let found = SYSTEM_BUNDLES.iter().find_map(|path| {
        let certs: Vec<_> = CertificateDer::pem_file_iter(path).ok()?.filter_map(std::result::Result::ok).collect();
        (!certs.is_empty()).then_some(certs)
    });
    if found.is_none() {
        log::error!("no root certificates: set SSL_CERT_FILE, or build with the Cargo feature `bundle-certificates`");
    }
    found
}

/// `host` as a TLS server name.
pub(crate) fn server_name(host: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(host.to_string()).map_err(|e| Error::transport(format!("invalid TLS server name {host}: {e}")))
}

/// Client TLS config: [`ca_bundle`], else the Mozilla roots (feature `bundle-certificates`); no verification when asked.
pub fn tls_config(verify: bool) -> std::result::Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    let config = if verify {
        let mut roots = RootCertStore::empty();
        match ca_bundle() {
            Some(certs) => {
                roots.add_parsable_certificates(certs.iter().cloned());
            }
            #[cfg(feature = "bundle-certificates")]
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            #[cfg(not(feature = "bundle-certificates"))]
            None => {}
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

/// Connect a Unix stream socket: a path, or a Linux abstract name after a leading NUL.
#[cfg(unix)]
pub(crate) fn unix_connect(path: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    match path.strip_prefix('\0') {
        Some(name) => unix_connect_abstract(name),
        None => std::os::unix::net::UnixStream::connect(path),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_connect_abstract(name: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
    std::os::unix::net::UnixStream::connect_addr(&addr)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn unix_connect_abstract(_: &str) -> std::io::Result<std::os::unix::net::UnixStream> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "abstract sockets exist only on Linux"))
}

/// Channel binding data for a TLS client session (see [`crate::Conn::channel_binding`]). `tls-exporter` needs TLS 1.3 (RFC 9266 forbids it on TLS 1.2 without extended master secret).
pub(crate) fn channel_binding(
    conn: &rustls::ClientConnection,
    kind: crate::transport::ChannelBinding,
) -> Option<Vec<u8>> {
    use crate::transport::ChannelBinding;
    match kind {
        ChannelBinding::TlsExporter => {
            if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
                return None;
            }
            conn.export_keying_material(vec![0u8; 32], b"EXPORTER-Channel-Binding", None).ok()
        }
        ChannelBinding::TlsServerEndPoint => server_end_point(conn.peer_certificates()?.first()?),
    }
}

/// RFC 5929 `tls-server-end-point`: the certificate hashed with its signature's hash, SHA-256 for MD5 and SHA-1. `None` for other algorithms (RSASSA-PSS, Ed25519), which the RFC leaves undefined.
fn server_end_point(der: &[u8]) -> Option<Vec<u8>> {
    let (cert, _) = der_seq(der)?;
    let (_tbs, rest) = der_element(cert)?;
    let (alg, _) = der_seq(rest)?;
    let (oid, _) = der_element(alg)?;
    const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    const ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04];
    let digest = match oid.strip_prefix(RSA).or_else(|| oid.strip_prefix(ECDSA)) {
        // md5/sha1WithRSAEncryption, sha256WithRSAEncryption, ecdsa-with-SHA1, ecdsa-with-SHA256
        Some([0x04] | [0x05] | [0x0b] | [0x01] | [0x03, 0x02]) => &ring::digest::SHA256,
        Some([0x0c] | [0x03, 0x03]) => &ring::digest::SHA384,
        Some([0x0d] | [0x03, 0x04]) => &ring::digest::SHA512,
        _ => return None,
    };
    Some(ring::digest::digest(digest, der).as_ref().to_vec())
}

/// The content of a DER SEQUENCE at the start of `b`, and what follows it.
fn der_seq(b: &[u8]) -> Option<(&[u8], &[u8])> {
    if *b.first()? != 0x30 {
        return None;
    }
    der_element(b)
}

/// The content of the DER element at the start of `b` (definite lengths only), and what follows it.
fn der_element(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *b.get(1)?;
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let len = b.get(2..2 + n)?.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x));
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((b.get(head..end)?, b.get(end..)?))
}

#[cfg(test)]
mod channel_binding_tests {
    use super::*;

    /// A certificate-shaped DER: `SEQUENCE { tbs, SEQUENCE { oid, NULL }, BIT STRING }`.
    fn cert(oid: &[u8]) -> Vec<u8> {
        let tbs = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut alg = vec![0x06, u8::try_from(oid.len()).unwrap()];
        alg.extend_from_slice(oid);
        alg.extend_from_slice(&[0x05, 0x00]);
        let mut body = tbs.to_vec();
        body.extend_from_slice(&[0x30, u8::try_from(alg.len()).unwrap()]);
        body.extend_from_slice(&alg);
        body.extend_from_slice(&[0x03, 0x02, 0x00, 0xff]);
        let mut der = vec![0x30, u8::try_from(body.len()).unwrap()];
        der.extend_from_slice(&body);
        der
    }

    #[test]
    fn server_end_point_hashes() {
        let sha256_rsa = cert(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
        assert_eq!(server_end_point(&sha256_rsa), Some(crate::crypto::sha256(&sha256_rsa)));
        let sha1_rsa = cert(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]);
        assert_eq!(server_end_point(&sha1_rsa), Some(crate::crypto::sha256(&sha1_rsa)));
        let ecdsa_384 = cert(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]);
        assert_eq!(server_end_point(&ecdsa_384).map(|h| h.len()), Some(48));
        let ecdsa_512 = cert(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]);
        assert_eq!(server_end_point(&ecdsa_512), Some(crate::crypto::sha512(&ecdsa_512)));
        assert_eq!(server_end_point(&cert(&[0x2b, 0x65, 0x70])), None, "Ed25519 is undefined");
        assert_eq!(server_end_point(&[0x30, 0x05, 0x01]), None, "truncated");
    }
}
