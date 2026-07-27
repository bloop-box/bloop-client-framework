//! The client handle, its builder, and the background connection task.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bloop_protocol::frame::RawMessage;
use bloop_protocol::message::{
    AchievementRecord, Bloop, BloopAccepted, PreloadCheck, PreloadMatch, PreloadMismatch,
    RetrieveAudio,
};
use bloop_protocol::set::{Payload, encode_message};
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
    pub host: String,
    pub port: u16,
    pub client_id: String,
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
    Connected { capabilities: Capabilities },

    /// The server rejected the credentials.
    InvalidCredentials,
}

/// How the client behaves after the server rejects its credentials.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
        audio_manifest_hash: DataHash,
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
    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
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
    ///         let list = session.custom(PhoneNumberPreload).await?;
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
        })
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

impl Default for BloopClientBuilder {
    fn default() -> Self {
        Self::new()
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
    /// to [`Unconfigured`](ConnectionStatus::Unconfigured).
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
    /// Bounded to a few seconds; queued requests ahead of the shutdown are
    /// allowed to finish, but a stalled connection cannot hold it up
    /// indefinitely.
    pub async fn shutdown(self) {
        let (response_tx, response_rx) = oneshot::channel();

        if self
            .command_tx
            .send(Command::Shutdown {
                response: response_tx,
            })
            .await
            .is_ok()
        {
            let _ = time::timeout(Duration::from_secs(5), response_rx).await;
        }
    }

    async fn send_request(&self, message: RawMessage) -> Result<RawMessage, RequestError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.command_tx
            .send(Command::Request {
                message,
                response: response_tx,
            })
            .await
            .map_err(|_| RequestError::Shutdown)?;

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

        if let Some(mut connection) = self.connection.take() {
            connection.quit().await;
        }
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
                let _ = self.status_tx.send(if config.is_some() {
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

                match connection.request_raw(&message).await {
                    Ok(raw) => {
                        let _ = response.send(Ok(raw));
                    }
                    Err(error) => {
                        warn!("lost connection due to: {}", error);
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
                let _ = self.status_tx.send(ConnectionStatus::Disconnected);
                let _ = response.send(());
            }
        }
    }

    async fn handle_tick(&mut self) {
        if self.shutdown {
            return;
        }

        if let Some(connection) = self.connection.as_mut() {
            if let Err(error) = connection.ping().await {
                warn!("ping failed: {}", error);
                self.drop_connection();
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

        match connect(config, &self.connector, &self.options).await {
            Ok(ConnectOutcome::Connected(mut connection)) => {
                if let Some(hook) = self.on_connect.clone() {
                    let mut session = Session::new(&mut connection);

                    if let Err(error) = hook(&mut session).await {
                        warn!("on-connect hook failed: {}", error);
                        connection.quit().await;
                        return;
                    }
                }

                self.credentials_invalid = false;
                let _ = self.status_tx.send(ConnectionStatus::Connected {
                    capabilities: connection.capabilities(),
                });
                self.connection = Some(connection);
            }
            Ok(ConnectOutcome::InvalidCredentials) => {
                self.credentials_invalid = true;
                let _ = self.status_tx.send(ConnectionStatus::InvalidCredentials);
            }
            Err(error) => {
                error!("failed to connect to server: {}", error);
            }
        }
    }

    fn drop_connection(&mut self) {
        self.connection = None;
        let _ = self.status_tx.send(ConnectionStatus::Disconnected);
    }
}
