//! TLS connector construction.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use thiserror::Error;
use tokio_rustls::TlsConnector;
use tracing::warn;

/// Errors that can occur while constructing the TLS connector.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// The platform's native certificate store could not be loaded.
    #[error("failed to load native certificates: {0}")]
    NativeCerts(String),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

/// Source of the root certificates used to verify the server.
#[derive(Clone, Copy, Debug, Default)]
pub enum RootCertSource {
    /// The built-in `webpki-roots` bundle.
    #[default]
    BuiltIn,

    /// The platform's native certificate store.
    Native,

    /// No verification at all; accepts any certificate.
    ///
    /// Only use this for testing.
    DangerousDisabled,
}

pub(crate) fn create_connector(source: RootCertSource) -> Result<TlsConnector, TlsError> {
    let root_cert_store = match source {
        RootCertSource::BuiltIn => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        },
        RootCertSource::Native => {
            let mut root_cert_store = RootCertStore::empty();
            let result = rustls_native_certs::load_native_certs();

            if !result.errors.is_empty() {
                return Err(TlsError::NativeCerts(format!("{:?}", result.errors)));
            }

            for cert in result.certs {
                root_cert_store.add(cert)?;
            }

            root_cert_store
        }
        RootCertSource::DangerousDisabled => {
            warn!("certificate verification is disabled; only use this for testing!");

            let client_config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SkipCertificateVerification::new())
                .with_no_client_auth();

            return Ok(TlsConnector::from(Arc::new(client_config)));
        }
    };

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// A certificate verifier that accepts anything.
#[derive(Debug)]
struct SkipCertificateVerification(rustls::crypto::CryptoProvider);

impl SkipCertificateVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            rustls::crypto::CryptoProvider::get_default()
                .map(|provider| provider.as_ref().clone())
                .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider),
        ))
    }
}

impl ServerCertVerifier for SkipCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
