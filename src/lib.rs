//! Client framework for the Bloop wire protocol.
//!
//! [`BloopClient`] owns the whole connection lifecycle a Bloop client needs:
//! DNS lookup, TLS, protocol handshake, authentication, keep-alive pings,
//! and reconnecting after failures. Applications observe the connection
//! through a status watch and perform strictly serialized request-response
//! exchanges, either through the typed standard operations or through
//! [`Request`]-implementing extension messages defined with the
//! [`bloop_protocol`] derives.
//!
//! # Examples
//!
//! ```no_run
//! use bloop_client_framework::{BloopClient, ConnectionConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = BloopClient::builder()
//!     .config(ConnectionConfig {
//!         host: "bloop.example.com".to_string(),
//!         port: 12345,
//!         client_id: "client".to_string(),
//!         client_secret: "secret".to_string(),
//!     })
//!     .build()?;
//!
//! let mut status = client.status();
//! status.wait_for(|status| matches!(status, bloop_client_framework::ConnectionStatus::Connected { .. })).await?;
//!
//! let uid = bloop_protocol::NfcUid::try_from(&[1u8, 2, 3, 4][..])?;
//! let achievements = client.bloop(uid).await?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "audio")]
pub mod audio;
mod audio_cache;
mod client;
mod connection;
#[cfg(feature = "nfc")]
pub mod nfc;
mod request;
mod tls;

pub use bloop_protocol;

pub use audio_cache::{AudioCache, AudioCacheError};
pub use client::{
    BloopClient, BloopClientBuilder, ConnectionConfig, ConnectionStatus, InvalidCredentialsPolicy,
    OnConnectError, OnConnectFuture, PreloadOutcome,
};
pub use connection::Session;
pub use request::{Request, RequestError};
pub use tls::{RootCertSource, TlsError};
