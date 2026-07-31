//! Loopback tests running the client framework against the real
//! bloop-server-framework listener over localhost TLS.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use argon2::password_hash::PasswordHashString;
use bloop_client_framework::{
    BloopClient, ConnectionConfig, ConnectionStatus, InvalidCredentialsPolicy, PreloadOutcome,
    Request, RequestError, RootCertSource,
};
use bloop_protocol::message::{AchievementRecord, ErrorResponse};
use bloop_protocol::{Capabilities, DataHash, Decode, Encode, MessageSet, NfcUid, Payload};
use bloop_server_framework::engine::EngineRequest;
use bloop_server_framework::message::{AudioData, BloopAccepted, PreloadMatch, ServerMessage};
use bloop_server_framework::network::{
    CustomOutcome, CustomRequestMessage, NetworkListenerBuilder,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use uuid::Uuid;

#[derive(Clone, Debug, Decode, Encode, Eq, Payload, PartialEq)]
#[bloop(opcode = 0x80)]
struct EchoRequest {
    text: String,
}

#[derive(Clone, Debug, Decode, Encode, Eq, Payload, PartialEq)]
#[bloop(opcode = 0x81)]
struct EchoResponse {
    text: String,
}

impl Request for EchoRequest {
    type Response = EchoResponse;
}

#[derive(Clone, Debug, Eq, MessageSet, PartialEq)]
enum TestRequest {
    Echo(EchoRequest),
}

#[derive(Clone, Debug, Eq, MessageSet, PartialEq)]
enum TestResponse {
    Echo(EchoResponse),
}

const ACHIEVEMENT_ID: Uuid = Uuid::from_bytes([7; 16]);

/// Spawns a full server on an ephemeral localhost port and returns its port.
async fn spawn_server() -> u16 {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let port = free_port();

    let mut clients = HashMap::new();
    clients.insert(
        "client".to_string(),
        PasswordHashString::new(
            "$argon2id$v=19$m=10,t=1,p=1$THh0RHE5YWNkQUZNa2lqUA$dmB4X7J49jjCGA",
        )
        .unwrap(),
    );

    let (engine_tx, mut engine_rx) =
        mpsc::channel::<(EngineRequest, oneshot::Sender<ServerMessage>)>(8);
    let (event_tx, _) = broadcast::channel(8);
    let (custom_tx, mut custom_rx) =
        mpsc::channel::<CustomRequestMessage<TestRequest, TestResponse>>(8);

    tokio::spawn(async move {
        while let Some((request, response)) = engine_rx.recv().await {
            let message: ServerMessage = match request {
                EngineRequest::Bloop { nfc_uid, .. } => {
                    if nfc_uid.as_bytes() == [1, 2, 3, 4] {
                        BloopAccepted {
                            achievements: vec![AchievementRecord {
                                id: ACHIEVEMENT_ID,
                                audio_hash: Some(DataHash::try_from(vec![9u8; 16]).unwrap()),
                            }],
                        }
                        .into()
                    } else {
                        ServerMessage::Error(ErrorResponse::UnknownNfcUid)
                    }
                }
                EngineRequest::RetrieveAudio { .. } => AudioData {
                    data: vec![1, 2, 3],
                }
                .into(),
                EngineRequest::PreloadCheck { .. } => PreloadMatch.into(),
            };

            let _ = response.send(message);
        }
    });

    tokio::spawn(async move {
        while let Some(request) = custom_rx.recv().await {
            let TestRequest::Echo(echo) = request.request;

            if echo.text == "kill" {
                // Dropping the response sender makes the listener tear the
                // connection down; used to provoke a server-side loss.
                continue;
            }

            let outcome = if echo.text == "fail" {
                CustomOutcome::Error(ErrorResponse::Custom(0x90))
            } else {
                CustomOutcome::Response(
                    EchoResponse {
                        text: echo.text.chars().rev().collect(),
                    }
                    .into(),
                )
            };

            let _ = request.response.send(outcome);
        }
    });

    let listener = NetworkListenerBuilder::new()
        .address(format!("127.0.0.1:{port}"))
        .cert_path("tests/fixtures/cert.pem")
        .key_path("tests/fixtures/key.pem")
        .clients(Arc::new(tokio::sync::RwLock::new(clients)))
        .engine_tx(engine_tx)
        .event_tx(event_tx)
        .custom_req_tx(custom_tx)
        .build()
        .unwrap();

    tokio::spawn(async move {
        let _ = listener.listen().await;
    });

    port
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(port: u16, client_secret: &str) -> ConnectionConfig {
    ConnectionConfig {
        host: "127.0.0.1".to_string(),
        port,
        client_id: "client".to_string(),
        client_secret: client_secret.to_string(),
    }
}

fn client_builder(port: u16) -> bloop_client_framework::BloopClientBuilder {
    BloopClient::builder()
        .config(config(port, "secret"))
        .root_cert_source(RootCertSource::DangerousDisabled)
        .ping_interval(Duration::from_millis(100))
}

async fn wait_connected(client: &BloopClient) -> Capabilities {
    let mut status = client.status();

    let status = tokio::time::timeout(
        Duration::from_secs(5),
        status.wait_for(|status| matches!(status, ConnectionStatus::Connected { .. })),
    )
    .await
    .expect("connect timed out")
    .unwrap();

    match *status {
        ConnectionStatus::Connected { capabilities, .. } => capabilities,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn connects_and_reports_capabilities() {
    let port = spawn_server().await;
    let client = client_builder(port).build().unwrap();

    let capabilities = wait_connected(&client).await;
    assert!(capabilities.contains(Capabilities::PreloadCheck));

    client.shutdown().await;
}

#[tokio::test]
async fn standard_operations_round_trip() {
    let port = spawn_server().await;
    let client = client_builder(port).build().unwrap();
    wait_connected(&client).await;

    let achievements = client
        .bloop(NfcUid::try_from(&[1u8, 2, 3, 4][..]).unwrap())
        .await
        .unwrap();
    assert_eq!(achievements.len(), 1);
    assert_eq!(achievements[0].id, ACHIEVEMENT_ID);

    let error = client
        .bloop(NfcUid::try_from(&[9u8, 9, 9, 9][..]).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RequestError::Error(ErrorResponse::UnknownNfcUid)
    ));

    let audio = client.retrieve_audio(ACHIEVEMENT_ID).await.unwrap();
    assert_eq!(audio, vec![1, 2, 3]);

    let outcome = client.preload_check(None).await.unwrap();
    assert_eq!(outcome, PreloadOutcome::Match);

    client.shutdown().await;
}

#[tokio::test]
async fn custom_requests_are_typed() {
    let port = spawn_server().await;
    let client = client_builder(port).build().unwrap();
    wait_connected(&client).await;

    let response = client
        .custom(EchoRequest {
            text: "hi".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(response.text, "ih");

    let error = client
        .custom(EchoRequest {
            text: "fail".to_string(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RequestError::Error(ErrorResponse::Custom(0x90))
    ));

    client.shutdown().await;
}

#[tokio::test]
async fn invalid_credentials_latch() {
    let port = spawn_server().await;
    let client = BloopClient::builder()
        .config(config(port, "wrong-secret"))
        .root_cert_source(RootCertSource::DangerousDisabled)
        .ping_interval(Duration::from_millis(100))
        .invalid_credentials_policy(InvalidCredentialsPolicy::Latch)
        .build()
        .unwrap();

    let mut status = client.status();
    tokio::time::timeout(
        Duration::from_secs(5),
        status.wait_for(|status| matches!(status, ConnectionStatus::InvalidCredentials)),
    )
    .await
    .expect("latch timed out")
    .unwrap();

    // New credentials clear the latch and connect.
    client
        .configure(Some(config(port, "secret")))
        .await
        .unwrap();
    wait_connected(&client).await;

    client.shutdown().await;
}

#[tokio::test]
async fn on_connect_hook_runs_before_connected() {
    let port = spawn_server().await;

    let (preload_tx, mut preload_rx) = mpsc::channel::<String>(1);

    let client = client_builder(port)
        .on_connect(move |session| {
            let preload_tx = preload_tx.clone();

            Box::pin(async move {
                let response = session
                    .custom(EchoRequest {
                        text: "preload".to_string(),
                    })
                    .await?;

                preload_tx.send(response.text).await?;
                Ok(())
            })
        })
        .build()
        .unwrap();

    wait_connected(&client).await;

    // The hook's result must already be there once Connected is observable.
    let preloaded = preload_rx.try_recv().expect("hook did not run first");
    assert_eq!(preloaded, "daolerp");

    client.shutdown().await;
}

#[tokio::test]
async fn audio_cache_downloads_and_prunes() {
    use bloop_client_framework::AudioCache;

    let port = spawn_server().await;
    let client = client_builder(port).build().unwrap();
    wait_connected(&client).await;

    let dir = tempfile::tempdir().unwrap();
    let cache = AudioCache::new(dir.path());

    let record = AchievementRecord {
        id: ACHIEVEMENT_ID,
        audio_hash: Some(DataHash::try_from(vec![9u8; 16]).unwrap()),
    };

    let path = cache.ensure(&client, &record).await.unwrap().unwrap();
    assert_eq!(tokio::fs::read(&path).await.unwrap(), vec![1, 2, 3]);

    // A second ensure is served from disk.
    let again = cache.ensure(&client, &record).await.unwrap().unwrap();
    assert_eq!(again, path);

    // Records without audio have no cache entry.
    let silent = AchievementRecord {
        id: Uuid::from_bytes([8; 16]),
        audio_hash: None,
    };
    assert!(cache.ensure(&client, &silent).await.unwrap().is_none());

    // Sync prunes files no record refers to anymore.
    let stale = dir.path().join("stale.mp3");
    tokio::fs::write(&stale, b"junk").await.unwrap();

    assert!(
        cache
            .sync(&client, &[record, silent])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!stale.exists());
    assert!(path.exists());

    client.shutdown().await;
}

#[tokio::test]
async fn reconnects_after_connection_loss() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let port = spawn_server().await;

    let connect_count = Arc::new(AtomicUsize::new(0));
    let hook_count = connect_count.clone();

    let client = client_builder(port)
        .on_connect(move |_session| {
            let hook_count = hook_count.clone();

            Box::pin(async move {
                hook_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })
        .build()
        .unwrap();

    wait_connected(&client).await;

    let error = client
        .custom(EchoRequest {
            text: "kill".to_string(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error, RequestError::Disconnected));

    wait_connected(&client).await;
    assert_eq!(connect_count.load(Ordering::SeqCst), 2);

    // The fresh connection is fully usable.
    let response = client
        .custom(EchoRequest {
            text: "hi".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(response.text, "ih");

    client.shutdown().await;
}

#[tokio::test]
async fn unconfigured_client_waits_for_configuration() {
    let port = spawn_server().await;
    let client = BloopClient::builder()
        .root_cert_source(RootCertSource::DangerousDisabled)
        .ping_interval(Duration::from_millis(100))
        .build()
        .unwrap();

    assert_eq!(*client.status().borrow(), ConnectionStatus::Unconfigured);

    let error = client
        .bloop(NfcUid::try_from(&[1u8, 2, 3, 4][..]).unwrap())
        .await
        .unwrap_err();
    assert!(matches!(error, RequestError::Disconnected));

    client
        .configure(Some(config(port, "secret")))
        .await
        .unwrap();
    wait_connected(&client).await;

    client.shutdown().await;
}
