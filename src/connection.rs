//! Connection establishment and the per-connection request primitive.

use std::pin::Pin;
use std::time::Duration;

use bloop_protocol::Capabilities;
use bloop_protocol::codec::EncodeError;
use bloop_protocol::frame::{FrameError, RawMessage, read_frame, write_frame};
use bloop_protocol::message::{
    Authentication, AuthenticationAccepted, ClientHandshake, ErrorResponse, Ping, Pong, Quit,
    ServerHandshake,
};
use bloop_protocol::set::encode_message;
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::net::{TcpStream, lookup_host};
use tokio_io_timeout::TimeoutStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use uuid::Uuid;

use crate::client::ConnectionConfig;
use crate::request::{Request, RequestError, decode_response};

type Stream = Pin<Box<TimeoutStream<TlsStream<TcpStream>>>>;

/// Errors that can occur while establishing a connection.
#[derive(Debug, Error)]
pub(crate) enum ConnectError {
    #[error("could not resolve {0}")]
    Resolve(String),

    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Frame(#[from] FrameError),

    #[error(transparent)]
    Encode(#[from] EncodeError),

    #[error("connection attempt timed out")]
    Timeout,

    #[error("server accepted unsupported version {0}")]
    UnsupportedVersion(u8),

    #[error("server does not support protocol version 3")]
    UnsupportedVersionRange,

    #[error("server sent an unexpected message during connect: {0:?}")]
    Unexpected(RequestError),
}

pub(crate) struct ConnectOptions {
    pub io_timeout: Duration,
    pub max_payload_len: u32,
}

pub(crate) enum ConnectOutcome {
    Connected(Connection),
    InvalidCredentials,
}

/// An established, authenticated connection.
pub(crate) struct Connection {
    stream: Stream,
    capabilities: Capabilities,
    max_payload_len: u32,
}

impl Connection {
    /// Performs one request-response exchange with raw frames.
    pub async fn request_raw(&mut self, message: &RawMessage) -> Result<RawMessage, FrameError> {
        write_frame(&mut self.stream, message).await?;
        read_frame(&mut self.stream, self.max_payload_len).await
    }

    /// Sends a ping and awaits the pong.
    pub async fn ping(&mut self) -> Result<(), RequestError> {
        let raw = self
            .request_raw(&encode_message(&Ping)?)
            .await
            .map_err(|error| {
                tracing::warn!("ping transport error: {}", error);
                RequestError::Disconnected
            })?;

        decode_response::<Pong>(raw)?;
        Ok(())
    }

    /// Announces the disconnect to the server; best effort.
    pub async fn quit(&mut self) {
        if let Ok(message) = encode_message(&Quit) {
            let _ = write_frame(&mut self.stream, &message).await;
        }
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }
}

/// A connection handed to the on-connect hook.
///
/// Runs requests directly on the fresh connection, before the client reports
/// [`Connected`](crate::ConnectionStatus::Connected). A hook failure fails
/// the connection attempt.
pub struct Session<'connection> {
    connection: &'connection mut Connection,
}

impl Session<'_> {
    pub(crate) fn new(connection: &mut Connection) -> Session<'_> {
        Session { connection }
    }

    /// Returns the capabilities the server declared in its handshake.
    pub fn capabilities(&self) -> Capabilities {
        self.connection.capabilities()
    }

    /// Performs a typed custom request.
    ///
    /// # Errors
    ///
    /// See [`RequestError`].
    pub async fn custom<M: Request>(&mut self, message: M) -> Result<M::Response, RequestError> {
        let raw = self
            .connection
            .request_raw(&encode_message(&message)?)
            .await
            .map_err(|_| RequestError::Disconnected)?;

        decode_response(raw)
    }

    /// Performs a raw frame exchange.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Disconnected`] if the connection fails.
    pub async fn request_raw(&mut self, message: &RawMessage) -> Result<RawMessage, RequestError> {
        self.connection
            .request_raw(message)
            .await
            .map_err(|_| RequestError::Disconnected)
    }

    /// Requests the audio data for an achievement.
    ///
    /// # Errors
    ///
    /// See [`RequestError`]; a missing audio file arrives as
    /// [`ErrorResponse::AudioUnavailable`].
    pub async fn retrieve_audio(&mut self, achievement_id: Uuid) -> Result<Vec<u8>, RequestError> {
        let raw = self
            .connection
            .request_raw(&encode_message(&bloop_protocol::message::RetrieveAudio {
                achievement_id,
            })?)
            .await
            .map_err(|_| RequestError::Disconnected)?;

        decode_response::<bloop_protocol::message::AudioData>(raw).map(|audio| audio.data)
    }
}

/// Establishes, negotiates, and authenticates a connection.
pub(crate) async fn connect(
    config: &ConnectionConfig,
    connector: &TlsConnector,
    options: &ConnectOptions,
) -> Result<ConnectOutcome, ConnectError> {
    // The per-operation stream timeouts only exist after the TLS handshake;
    // this bound keeps a stalled resolve, TCP connect, or TLS handshake from
    // freezing the connection task indefinitely.
    let (tls_stream, local_ip) = tokio::time::timeout(options.io_timeout, async {
        let address = lookup_host((config.host.as_str(), config.port))
            .await
            .map_err(|_| ConnectError::Resolve(config.host.clone()))?
            .next()
            .ok_or_else(|| ConnectError::Resolve(config.host.clone()))?;

        let tcp_stream = TcpStream::connect(&address).await?;
        let local_ip = tcp_stream.local_addr()?.ip();

        let domain = ServerName::try_from(config.host.as_str())
            .map_err(|_| ConnectError::InvalidDnsName(config.host.clone()))?
            .to_owned();

        let tls_stream = connector.connect(domain, tcp_stream).await?;

        Ok::<_, ConnectError>((tls_stream, local_ip))
    })
    .await
    .map_err(|_| ConnectError::Timeout)??;

    let mut timeout_stream = TimeoutStream::new(tls_stream);
    timeout_stream.set_read_timeout(Some(options.io_timeout));
    timeout_stream.set_write_timeout(Some(options.io_timeout));

    let mut connection = Connection {
        stream: Box::pin(timeout_stream),
        capabilities: Capabilities::none(),
        max_payload_len: options.max_payload_len,
    };

    connection.capabilities = negotiate_version(&mut connection).await?;

    let authenticated = authenticate(&mut connection, config, local_ip).await?;

    if !authenticated {
        return Ok(ConnectOutcome::InvalidCredentials);
    }

    Ok(ConnectOutcome::Connected(connection))
}

async fn negotiate_version(connection: &mut Connection) -> Result<Capabilities, ConnectError> {
    let raw = connection
        .request_raw(&encode_message(&ClientHandshake {
            min_version: 3,
            max_version: 3,
        })?)
        .await?;

    let handshake = match decode_response::<ServerHandshake>(raw) {
        Ok(handshake) => handshake,
        Err(RequestError::Error(ErrorResponse::UnsupportedVersionRange)) => {
            return Err(ConnectError::UnsupportedVersionRange);
        }
        Err(error) => return Err(ConnectError::Unexpected(error)),
    };

    if handshake.accepted_version != 3 {
        return Err(ConnectError::UnsupportedVersion(handshake.accepted_version));
    }

    Ok(handshake.capabilities)
}

async fn authenticate(
    connection: &mut Connection,
    config: &ConnectionConfig,
    local_ip: std::net::IpAddr,
) -> Result<bool, ConnectError> {
    let raw = connection
        .request_raw(&encode_message(&Authentication {
            client_id: config.client_id.clone(),
            client_secret: config.client_secret.clone(),
            ip_address: local_ip,
        })?)
        .await?;

    match decode_response::<AuthenticationAccepted>(raw) {
        Ok(_) => Ok(true),
        Err(RequestError::Error(ErrorResponse::InvalidCredentials)) => Ok(false),
        Err(error) => Err(ConnectError::Unexpected(error)),
    }
}
