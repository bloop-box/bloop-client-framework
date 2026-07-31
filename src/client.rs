//! The client handle, its builder, and the background connection task.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bloop_protocol::frame::RawMessage;
use bloop_protocol::message::{
    AchievementRecord, Bloop, BloopAccepted, ErrorResponse, PreloadCheck, PreloadMatch,
    PreloadMismatch, RetrieveAudio,
};
use bloop_protocol::set::{Payload, decode_message, encode_message};
use bloop_protocol::{Capabilities, DataHash, NfcUid};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::{select, time};
#[cfg(feature = "tokio-graceful-shutdown")]
use tokio_graceful_shutdown::{IntoSubsystem, SubsystemHandle};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::connection::{ConnectOptions, ConnectOutcome, Connection, Session, connect};
use crate::request::{Request, RequestError, decode_response};
use crate::tls::{RootCertSource, TlsError, create_connector};

/// Server address and credentials for a connection.
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    /// Host name or address of the server.
    pub host: String,

    /// Port the server listens on.
    pub port: u16,

    /// Client ID sent during authentication.
    pub client_id: String,

    /// Client secret sent during authentication.
    pub client_secret: String,
}

/// The client's connection state, observable via [`BloopClient::status`].
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum ConnectionStatus {
    /// No connection configuration is set.
    Unconfigured,

    /// Configured but not currently connected; the client keeps retrying.
    Disconnected,

    /// Connected and authenticated.
    #[non_exhaustive]
    Connected {
        /// The capabilities the server declared in its handshake.
        capabilities: Capabilities,
    },

    /// The server rejected the credentials.
    InvalidCredentials,

    /// The client was shut down and will not reconnect.
    Shutdown,
}

/// How the client behaves after the server rejects its credentials.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum InvalidCredentialsPolicy {
    /// Stop connecting until new credentials arrive via
    /// [`BloopClient::configure`].
    #[default]
    Latch,

    /// Keep retrying with the same credentials.
    Retry,
}

/// The result of a preload check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreloadOutcome {
    /// The cached audio assets are up to date.
    Match,

    /// The cache is outdated; the current manifest and asset list follow.
    Mismatch {
        /// Hash of the server's current audio manifest.
        audio_manifest_hash: DataHash,

        /// The full current achievement list.
        achievements: Vec<AchievementRecord>,
    },
}

/// The error type an on-connect hook may return.
pub type OnConnectError = Box<dyn std::error::Error + Send + Sync>;

/// The boxed future an on-connect hook returns.
pub type OnConnectFuture<'session> =
    Pin<Box<dyn Future<Output = Result<(), OnConnectError>> + Send + 'session>>;

type OnConnectFn = dyn for<'a, 'b> Fn(&'a mut Session<'b>) -> OnConnectFuture<'a> + Send + Sync;

#[derive(Debug)]
enum Command {
    Configure(Option<ConnectionConfig>),
    Request {
        message: RawMessage,
        response: oneshot::Sender<Result<RawMessage, RequestError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

/// Builder for [`BloopClient`].
///
/// All settings have defaults; a client built without
/// [`config`](Self::config) starts [`Unconfigured`] and waits for
/// [`BloopClient::configure`].
///
/// [`Unconfigured`]: ConnectionStatus::Unconfigured
pub struct BloopClientBuilder {
    config: Option<ConnectionConfig>,
    root_cert_source: RootCertSource,
    ping_interval: Duration,
    io_timeout: Duration,
    request_timeout: Duration,
    max_payload_len: u32,
    invalid_credentials_policy: InvalidCredentialsPolicy,
    on_connect: Option<Arc<OnConnectFn>>,
}

impl BloopClientBuilder {
    /// Creates a builder with default settings.
    pub fn new() -> Self {
        Self {
            config: None,
            root_cert_source: RootCertSource::default(),
            ping_interval: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(60),
            max_payload_len: 16 * 1024 * 1024,
            invalid_credentials_policy: InvalidCredentialsPolicy::default(),
            on_connect: None,
        }
    }

    /// Sets the initial connection configuration.
    pub fn config(mut self, config: ConnectionConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Selects the root certificates used to verify the server.
    pub fn root_cert_source(mut self, source: RootCertSource) -> Self {
        self.root_cert_source = source;
        self
    }

    /// Overrides the keep-alive interval, which doubles as the reconnect
    /// interval.
    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Overrides the per-operation read/write timeout on the stream.
    ///
    /// This is an idle timeout: it fires when the server sends nothing at
    /// all for the given duration. See also
    /// [`request_timeout`](Self::request_timeout).
    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Overrides the total deadline for a single request-response exchange.
    ///
    /// Unlike [`io_timeout`](Self::io_timeout), this bounds the whole
    /// exchange, so a server that keeps trickling bytes cannot hold a
    /// request (and with it the connection task) open indefinitely. The
    /// default of 60 seconds leaves room for a multi-MiB audio download on a
    /// slow link. The same deadline separately applies to each connection
    /// attempt, to the on-connect hook, and to enqueueing a request on a
    /// busy client, so a caller may wait a small multiple of it in the
    /// worst case.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Overrides the maximum payload length accepted from the server.
    ///
    /// The default of 16 MiB leaves room for audio data.
    pub fn max_payload_len(mut self, max_payload_len: u32) -> Self {
        self.max_payload_len = max_payload_len;
        self
    }

    /// Selects the behavior after the server rejects the credentials.
    pub fn invalid_credentials_policy(mut self, policy: InvalidCredentialsPolicy) -> Self {
        self.invalid_credentials_policy = policy;
        self
    }

    /// Registers a hook that runs inside every connection attempt.
    ///
    /// The hook runs after authentication but before the status flips to
    /// [`Connected`](ConnectionStatus::Connected); a hook error fails the
    /// attempt, and the client retries. Use it for work that must happen on
    /// every (re)connect, such as preloading extension data.
    ///
    /// All server I/O inside the hook must go through the [`Session`]: the
    /// hook runs on the client's own connection task, so calling methods on
    /// a captured [`BloopClient`] handle in the hook deadlocks the client.
    ///
    /// ```ignore
    /// let builder = builder.on_connect(|session| {
    ///     Box::pin(async move {
    ///         let list = session.custom(FetchHighScores).await?;
    ///         // store the list somewhere shared
    ///         Ok(())
    ///     })
    /// });
    /// ```
    pub fn on_connect<F>(mut self, hook: F) -> Self
    where
        F: for<'a, 'b> Fn(&'a mut Session<'b>) -> OnConnectFuture<'a> + Send + Sync + 'static,
    {
        self.on_connect = Some(Arc::new(hook));
        self
    }

    /// Builds the client and spawns its connection task.
    ///
    /// Must be called within a tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsError`] if the TLS connector cannot be constructed.
    pub fn build(self) -> Result<BloopClient, TlsError> {
        let connector = create_connector(self.root_cert_source)?;
        let (command_tx, command_rx) = mpsc::channel(16);

        let initial_status = if self.config.is_some() {
            ConnectionStatus::Disconnected
        } else {
            ConnectionStatus::Unconfigured
        };
        let (status_tx, status_rx) = watch::channel(initial_status);

        let task = ClientTask {
            connector,
            config: self.config,
            connection: None,
            command_rx,
            status_tx,
            ping_interval: self.ping_interval,
            request_timeout: self.request_timeout,
            options: ConnectOptions {
                io_timeout: self.io_timeout,
                max_payload_len: self.max_payload_len,
            },
            invalid_credentials_policy: self.invalid_credentials_policy,
            on_connect: self.on_connect,
            credentials_invalid: false,
            shutdown: false,
        };

        tokio::spawn(task.run());

        Ok(BloopClient {
            command_tx,
            status_rx,
            request_timeout: self.request_timeout,
        })
    }
}

impl Default for BloopClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BloopClientBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BloopClientBuilder")
            .field("config", &self.config)
            .field("root_cert_source", &self.root_cert_source)
            .field("ping_interval", &self.ping_interval)
            .field("io_timeout", &self.io_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("max_payload_len", &self.max_payload_len)
            .field(
                "invalid_credentials_policy",
                &self.invalid_credentials_policy,
            )
            .field("on_connect", &self.on_connect.as_ref().map(|_| "..."))
            .finish()
    }
}

/// A Bloop protocol client with automatic connection management.
///
/// The client owns a background task that connects, authenticates, sends
/// keep-alives, and reconnects on failure. Requests are strictly serialized,
/// matching the protocol's request-response flow. Dropping the client winds
/// the task down with a best-effort quit; [`shutdown`](Self::shutdown)
/// announces the disconnect explicitly.
#[derive(Clone, Debug)]
pub struct BloopClient {
    command_tx: mpsc::Sender<Command>,
    status_rx: watch::Receiver<ConnectionStatus>,
    request_timeout: Duration,
}

impl BloopClient {
    /// Creates a builder for a new client.
    pub fn builder() -> BloopClientBuilder {
        BloopClientBuilder::new()
    }

    /// Returns a watch of the connection status.
    pub fn status(&self) -> watch::Receiver<ConnectionStatus> {
        self.status_rx.clone()
    }

    /// Replaces the connection configuration at runtime.
    ///
    /// Drops any current connection, clears an invalid-credentials latch,
    /// and reconnects with the new configuration; `None` returns the client
    /// to [`Unconfigured`](ConnectionStatus::Unconfigured). After
    /// [`shutdown`](Self::shutdown) this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Shutdown`] if the client is gone.
    pub async fn configure(&self, config: Option<ConnectionConfig>) -> Result<(), RequestError> {
        self.command_tx
            .send(Command::Configure(config))
            .await
            .map_err(|_| RequestError::Shutdown)
    }

    /// Asks the server to verify a scanned NFC UID.
    ///
    /// # Errors
    ///
    /// See [`RequestError`]; an unknown or throttled UID arrives as
    /// [`ErrorResponse::UnknownNfcUid`] or [`ErrorResponse::NfcUidThrottled`].
    ///
    /// [`ErrorResponse::UnknownNfcUid`]: bloop_protocol::message::ErrorResponse::UnknownNfcUid
    /// [`ErrorResponse::NfcUidThrottled`]: bloop_protocol::message::ErrorResponse::NfcUidThrottled
    pub async fn bloop(&self, nfc_uid: NfcUid) -> Result<Vec<AchievementRecord>, RequestError> {
        let raw = self
            .send_request(encode_message(&Bloop { nfc_uid })?)
            .await?;
        decode_response::<BloopAccepted>(raw).map(|message| message.achievements)
    }

    /// Requests the audio data for an achievement.
    ///
    /// # Errors
    ///
    /// See [`RequestError`]; a missing audio file arrives as
    /// [`ErrorResponse::AudioUnavailable`].
    ///
    /// [`ErrorResponse::AudioUnavailable`]: bloop_protocol::message::ErrorResponse::AudioUnavailable
    pub async fn retrieve_audio(&self, achievement_id: Uuid) -> Result<Vec<u8>, RequestError> {
        let raw = self
            .send_request(encode_message(&RetrieveAudio { achievement_id })?)
            .await?;

        decode_response::<bloop_protocol::message::AudioData>(raw).map(|audio| audio.data)
    }

    /// Asks the server whether the cached audio assets are up to date.
    ///
    /// Only call this when the server declared
    /// [`Capabilities::PreloadCheck`] in its handshake (available via
    /// [`ConnectionStatus::Connected`]); servers without the capability
    /// answer with a fatal error and close the connection.
    ///
    /// # Errors
    ///
    /// See [`RequestError`].
    pub async fn preload_check(
        &self,
        audio_manifest_hash: Option<DataHash>,
    ) -> Result<PreloadOutcome, RequestError> {
        let raw = self
            .send_request(encode_message(&PreloadCheck {
                audio_manifest_hash,
            })?)
            .await?;

        if raw.message_type == PreloadMatch::OPCODE {
            decode_response::<PreloadMatch>(raw)?;
            return Ok(PreloadOutcome::Match);
        }

        decode_response::<PreloadMismatch>(raw).map(|mismatch| PreloadOutcome::Mismatch {
            audio_manifest_hash: mismatch.audio_manifest_hash,
            achievements: mismatch.achievements,
        })
    }

    /// Performs a typed custom request.
    ///
    /// # Errors
    ///
    /// See [`RequestError`]; extension-defined error codes arrive as
    /// [`ErrorResponse::Custom`].
    ///
    /// [`ErrorResponse::Custom`]: bloop_protocol::message::ErrorResponse::Custom
    pub async fn custom<M: Request>(&self, message: M) -> Result<M::Response, RequestError> {
        let raw = self.send_request(encode_message(&message)?).await?;
        decode_response(raw)
    }

    /// Performs a raw frame exchange.
    ///
    /// The escape hatch for extensions that fall outside the one-to-one
    /// request-response mapping of [`custom`](Self::custom).
    ///
    /// # Errors
    ///
    /// See [`RequestError`].
    pub async fn request_raw(&self, message: RawMessage) -> Result<RawMessage, RequestError> {
        self.send_request(message).await
    }

    /// Shuts the client down, announcing the disconnect to the server.
    ///
    /// Returns after a few seconds at the latest. Requests already queued
    /// ahead of the shutdown may outlive that bound; the connection task
    /// keeps draining them and winds down (announcing the disconnect,
    /// publishing [`ConnectionStatus::Shutdown`]) once it reaches the
    /// shutdown command.
    ///
    /// The shutdown affects the shared connection task: any surviving clones
    /// of the handle stay usable as values but every operation on them
    /// returns [`RequestError::Shutdown`].
    pub async fn shutdown(self) {
        let (response_tx, response_rx) = oneshot::channel();

        let _ = time::timeout(Duration::from_secs(5), async {
            if self
                .command_tx
                .send(Command::Shutdown {
                    response: response_tx,
                })
                .await
                .is_ok()
            {
                let _ = response_rx.await;
            }
        })
        .await;
    }

    async fn send_request(&self, message: RawMessage) -> Result<RawMessage, RequestError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.command_tx
            .send_timeout(
                Command::Request {
                    message,
                    response: response_tx,
                },
                self.request_timeout,
            )
            .await
            .map_err(|error| match error {
                mpsc::error::SendTimeoutError::Closed(_) => RequestError::Shutdown,
                mpsc::error::SendTimeoutError::Timeout(_) => RequestError::Disconnected,
            })?;

        response_rx.await.map_err(|_| RequestError::Shutdown)?
    }
}

struct ClientTask {
    connector: TlsConnector,
    config: Option<ConnectionConfig>,
    connection: Option<Connection>,
    command_rx: mpsc::Receiver<Command>,
    status_tx: watch::Sender<ConnectionStatus>,
    ping_interval: Duration,
    request_timeout: Duration,
    options: ConnectOptions,
    invalid_credentials_policy: InvalidCredentialsPolicy,
    on_connect: Option<Arc<OnConnectFn>>,
    credentials_invalid: bool,
    shutdown: bool,
}

impl ClientTask {
    async fn run(mut self) {
        let mut ticker = time::interval(self.ping_interval);
        ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        loop {
            select! {
                command = self.command_rx.recv() => match command {
                    Some(command) => self.handle_command(command).await,
                    None => break,
                },
                _ = ticker.tick() => self.handle_tick().await,
            }
        }

        // All handles are gone: announce the disconnect and let any
        // remaining status receivers observe a terminal state instead of a
        // stale one.
        if let Some(mut connection) = self.connection.take() {
            connection.quit().await;
        }

        self.set_status(ConnectionStatus::Shutdown);
    }

    async fn handle_command(&mut self, command: Command) {
        debug!("received command: {:?}", command);

        match command {
            Command::Configure(config) => {
                if self.shutdown {
                    return;
                }

                if let Some(mut connection) = self.connection.take() {
                    connection.quit().await;
                }

                self.credentials_invalid = false;
                self.set_status(if config.is_some() {
                    ConnectionStatus::Disconnected
                } else {
                    ConnectionStatus::Unconfigured
                });
                self.config = config;
            }
            Command::Request { message, response } => {
                if self.shutdown {
                    let _ = response.send(Err(RequestError::Shutdown));
                    return;
                }

                let Some(connection) = self.connection.as_mut() else {
                    let _ = response.send(Err(RequestError::Disconnected));
                    return;
                };

                match time::timeout(self.request_timeout, connection.request_raw(&message)).await {
                    Ok(Ok(raw)) => {
                        // A fatal protocol error means the server has
                        // already closed the connection; drop ours so the
                        // status watch does not keep claiming Connected
                        // until the next ping notices.
                        if raw.message_type == ErrorResponse::OPCODE
                            && decode_message::<ErrorResponse>(&raw)
                                .is_ok_and(|error| error.is_fatal())
                        {
                            warn!("server answered with a fatal error");
                            self.drop_connection();
                        }

                        let _ = response.send(Ok(raw));
                    }
                    Ok(Err(error)) => {
                        warn!("lost connection due to: {}", error);
                        self.drop_connection();
                        let _ = response.send(Err(RequestError::Disconnected));
                    }
                    Err(_) => {
                        warn!("request exceeded the request timeout");
                        self.drop_connection();
                        let _ = response.send(Err(RequestError::Disconnected));
                    }
                }
            }
            Command::Shutdown { response } => {
                if let Some(mut connection) = self.connection.take() {
                    connection.quit().await;
                }

                self.shutdown = true;
                self.set_status(ConnectionStatus::Shutdown);
                let _ = response.send(());
            }
        }
    }

    async fn handle_tick(&mut self) {
        if self.shutdown {
            return;
        }

        if let Some(connection) = self.connection.as_mut() {
            match time::timeout(self.request_timeout, connection.ping()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!("ping failed: {}", error);
                    self.drop_connection();
                }
                Err(_) => {
                    warn!("ping exceeded the request timeout");
                    self.drop_connection();
                }
            }

            return;
        }

        self.try_connect().await;
    }

    async fn try_connect(&mut self) {
        if self.credentials_invalid
            && self.invalid_credentials_policy == InvalidCredentialsPolicy::Latch
        {
            return;
        }

        let Some(config) = self.config.as_ref() else {
            return;
        };

        info!("trying to connect to server");

        let outcome = match time::timeout(
            self.request_timeout,
            connect(config, &self.connector, &self.options),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                error!("connection attempt exceeded the request timeout");
                self.set_status(ConnectionStatus::Disconnected);
                return;
            }
        };

        match outcome {
            Ok(ConnectOutcome::Connected(mut connection)) => {
                if let Some(hook) = self.on_connect.clone() {
                    let mut session = Session::new(&mut connection);

                    match time::timeout(self.request_timeout, hook(&mut session)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            warn!("on-connect hook failed: {}", error);
                            connection.quit().await;
                            self.set_status(ConnectionStatus::Disconnected);
                            return;
                        }
                        Err(_) => {
                            warn!("on-connect hook exceeded the request timeout");
                            self.set_status(ConnectionStatus::Disconnected);
                            return;
                        }
                    }
                }

                self.credentials_invalid = false;
                self.set_status(ConnectionStatus::Connected {
                    capabilities: connection.capabilities(),
                });
                self.connection = Some(connection);
            }
            Ok(ConnectOutcome::InvalidCredentials) => {
                self.credentials_invalid = true;
                self.set_status(ConnectionStatus::InvalidCredentials);
            }
            Err(error) => {
                error!("failed to connect to server: {}", error);

                // A network failure is not a credentials problem; without
                // this, a failed attempt under the Retry policy would leave
                // a stale InvalidCredentials on the watch.
                self.set_status(ConnectionStatus::Disconnected);
            }
        }
    }

    fn drop_connection(&mut self) {
        self.connection = None;
        self.set_status(ConnectionStatus::Disconnected);
    }

    /// Publishes a status, skipping the notification when it is unchanged.
    fn set_status(&self, status: ConnectionStatus) {
        self.status_tx.send_if_modified(|current| {
            if *current == status {
                false
            } else {
                *current = status;
                true
            }
        });
    }
}

/// Runs the client as a subsystem that quits cleanly on shutdown.
///
/// The connection task itself runs independently; this subsystem only waits
/// for the shutdown request and announces the disconnect to the server.
#[cfg(feature = "tokio-graceful-shutdown")]
impl IntoSubsystem<std::convert::Infallible> for BloopClient {
    async fn run(self, subsys: &mut SubsystemHandle) -> Result<(), std::convert::Infallible> {
        subsys.on_shutdown_requested().await;
        self.shutdown().await;

        Ok(())
    }
}
