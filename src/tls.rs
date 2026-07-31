//! TLS connector construction.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;
use thiserror::Error;
use tokio_rustls::TlsConnector;
use tracing::warn;

/// Errors that can occur while constructing the TLS connector.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsError {
    /// Constructing the rustls client configuration failed.
    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

/// Source of the root certificates used to verify the server.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub enum RootCertSource {
    /// The operating system's certificate verifier.
    ///
    /// On Linux this loads the system CA bundle (the `ca-certificates`
    /// package on Debian) once at startup; locally installed CAs require an
    /// application restart to be picked up.
    #[default]
    Platform,

    /// No verification at all; accepts any certificate.
    ///
    /// Only use this for testing.
    DangerousDisabled,
}

pub(crate) fn create_connector(source: RootCertSource) -> Result<TlsConnector, TlsError> {
    // ClientConfig::builder() panics when no process-default crypto provider
    // can be resolved (e.g. two provider features enabled somewhere in the
    // dependency graph); passing the provider explicitly on both arms keeps
    // build() panic-free as its Result promises.
    let client_config = match source {
        RootCertSource::Platform => {
            ClientConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .with_platform_verifier()?
                .with_no_client_auth()
        }
        RootCertSource::DangerousDisabled => {
            warn!("certificate verification is disabled; only use this for testing!");

            let verifier = SkipCertificateVerification::new();
            let provider = Arc::new(verifier.0.clone());

            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };

    Ok(TlsConnector::from(Arc::new(client_config)))
}

fn default_provider() -> CryptoProvider {
    CryptoProvider::get_default()
        .map(|provider| provider.as_ref().clone())
        .unwrap_or_else(rustls::crypto::aws_lc_rs::default_provider)
}

/// A certificate verifier that accepts anything.
#[derive(Debug)]
struct SkipCertificateVerification(rustls::crypto::CryptoProvider);

impl SkipCertificateVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(default_provider()))
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
