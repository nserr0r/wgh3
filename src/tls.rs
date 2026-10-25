use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

pub const ALPN_H3: &[&[u8]] = &[b"h3"];
pub const ALPN_HTTPS: &[&[u8]] = &[b"h2", b"http/1.1"];

pub fn server_config(cert_path: &str, key_path: &str, alpn: &[&[u8]]) -> Result<rustls::ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut config = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

pub fn client_config(pin_sha256: Option<&str>, insecure: bool) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();

    let policy = match (pin_sha256, insecure) {
        (Some(pin), _) => Some(Policy::Pinned(parse_fingerprint(pin)?)),
        (None, true) => Some(Policy::AnyCertificate),
        (None, false) => None,
    };

    let mut config = match policy {
        Some(policy) => {
            let algorithms = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
            let verifier = Verifier { policy, algorithms };
            builder.dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth()
        }
        None => {
            let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };

    config.alpn_protocols = ALPN_H3.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(config)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("не удалось открыть сертификат {path}"))?;
    rustls_pemfile::certs(&mut BufReader::new(file)).collect::<std::result::Result<_, _>>().context("не удалось прочитать сертификаты")
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("не удалось открыть ключ {path}"))?;
    rustls_pemfile::private_key(&mut BufReader::new(file))?.context("приватный ключ не найден")
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32]> {
    let digits: String = value.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    let bytes = hex::decode(&digits).context("некорректный hex в pin_sha256")?;

    match bytes.try_into() {
        Ok(fingerprint) => Ok(fingerprint),
        Err(_) => bail!("pin_sha256 должен быть 32 байта"),
    }
}

#[derive(Debug)]
enum Policy {
    Pinned([u8; 32]),
    AnyCertificate,
}

#[derive(Debug)]
struct Verifier {
    policy: Policy,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match &self.policy {
            Policy::AnyCertificate => Ok(ServerCertVerified::assertion()),
            Policy::Pinned(expected) => {
                let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
                if actual == *expected {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General("отпечаток сертификата не совпадает".into()))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_accepts_colons_and_spaces() {
        let plain = "ab".repeat(32);
        let with_colons = vec!["AB"; 32].join(":");

        assert_eq!(parse_fingerprint(&plain).unwrap(), [0xab; 32]);
        assert_eq!(parse_fingerprint(&with_colons).unwrap(), [0xab; 32]);
        assert_eq!(parse_fingerprint(&format!(" {plain} ")).unwrap(), [0xab; 32]);
    }

    #[test]
    fn fingerprint_rejects_wrong_length_and_garbage() {
        assert!(parse_fingerprint(&"ab".repeat(31)).is_err());
        assert!(parse_fingerprint("zz").is_err());
    }
}
