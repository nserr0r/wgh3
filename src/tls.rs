use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use quinn::ClientConfig;
use quinn::ServerConfig;
use quinn::TransportConfig;
use rustls::DigitallySignedStruct;
use rustls::RootCertStore;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

pub fn server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

pub fn client_config(pin_sha256: Option<&str>, insecure: bool) -> Result<ClientConfig> {
    let builder = rustls::ClientConfig::builder();

    let mut tls = match (pin_sha256, insecure) {
        (Some(pin), _) => {
            let verifier = CustomVerifier { mode: VerifyMode::Pinned(parse_fingerprint(pin)?) };
            builder.dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth()
        }
        (None, true) => {
            let verifier = CustomVerifier { mode: VerifyMode::Insecure };
            builder.dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth()
        }
        (None, false) => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };

    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

pub fn rustls_server_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let mut tls = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];

    Ok(Arc::new(tls))
}

fn transport_config() -> Result<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(8 * 1024 * 1024);
    transport.stream_receive_window((4u32 * 1024 * 1024).into());
    transport.receive_window((16u32 * 1024 * 1024).into());
    transport.send_window(16 * 1024 * 1024);
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(transport)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).context("не удалось открыть сертификат")?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>().context("не удалось прочитать сертификаты")
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).context("не удалось открыть ключ")?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| anyhow!("приватный ключ не найден"))
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32]> {
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
    let bytes = hex::decode(&cleaned).context("некорректный hex в pin_sha256")?;

    if bytes.len() != 32 {
        return Err(anyhow!("pin_sha256 должен быть 32 байта"));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Debug)]
enum VerifyMode {
    Pinned([u8; 32]),
    Insecure,
}

#[derive(Debug)]
struct CustomVerifier {
    mode: VerifyMode,
}

impl ServerCertVerifier for CustomVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        match &self.mode {
            VerifyMode::Insecure => Ok(ServerCertVerified::assertion()),
            VerifyMode::Pinned(fingerprint) => {
                let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();

                if actual == *fingerprint {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General("отпечаток сертификата не совпадает".into()))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
