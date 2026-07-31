# Bloop Client Framework

This library handles the connection lifecycle for Bloop protocol clients: DNS lookup, TLS, protocol handshake,
authentication, keep-alive pings, and reconnecting after failures. Applications observe the connection through a
status watch and perform request-response exchanges through typed operations.

The wire format lives in the [bloop-protocol](https://github.com/bloop-box/bloop-protocol) crate.

## Quick start

```rust
use bloop_client_framework::{BloopClient, ConnectionConfig, ConnectionStatus};

let client = BloopClient::builder()
    .config(ConnectionConfig {
        host: "bloop.example.com".to_string(),
        port: 12345,
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
    })
    .build()?;

let mut status = client.status();
status.wait_for(|status| matches!(status, ConnectionStatus::Connected { .. })).await?;

let achievements = client.bloop(nfc_uid).await?;
let audio = client.retrieve_audio(achievement_id).await?;
```

The client can also start without configuration (status `Unconfigured`) and receive credentials at runtime via
`configure`, e.g. when they arrive on a provisioning tag. Rejected credentials latch the client until new ones
arrive; use `InvalidCredentialsPolicy::Retry` to keep retrying instead.

## Custom messages

Extensions define their messages with the `bloop-protocol` derives (direct dependency required, opcodes `0x80` and
above) and pair each request with its response type through the `Request` trait:

```rust
use bloop_client_framework::Request;
use bloop_protocol::{Decode, Encode, Payload};

#[derive(Debug, Encode, Decode, Payload)]
#[bloop(opcode = 0x80)]
struct SubmitScore {
    nfc_uid: NfcUid,
    score: u32,
}

#[derive(Debug, Encode, Decode, Payload)]
#[bloop(opcode = 0x81)]
struct ScoreAccepted {
    rank: u32,
}

impl Request for SubmitScore {
    type Response = ScoreAccepted;
}

// Fully typed request-response:
let accepted = client.custom(SubmitScore { nfc_uid, score }).await?;
```

Protocol errors, including extension-defined codes, arrive as `RequestError::Error(ErrorResponse)`. For exchanges
that fall outside the one-to-one mapping there is `request_raw`.

## On-connect hook

Work that must happen on every (re)connect, such as preloading extension data, runs inside the connection attempt,
before the status flips to `Connected`; a hook failure fails the attempt:

```rust
let builder = builder.on_connect(|session| {
    Box::pin(async move {
        let scores = session.custom(FetchHighScores).await?;
        // store the list somewhere shared
        Ok(())
    })
});
```

All server I/O inside the hook must go through the `Session`: the hook runs on the client's own connection task,
so calling methods on a captured `BloopClient` handle in the hook deadlocks the client. `AudioCache` accepts a
`&mut Session` for the same reason.

## Audio cache

`AudioCache` keeps achievement audio on disk, keyed by achievement ID and audio hash, so server-side updates
invalidate stale files naturally:

```rust
let cache = AudioCache::new("/var/cache/bloop/audio");

// On demand, e.g. when a bloop awards an achievement:
if let Some(path) = cache.ensure(&client, &record).await? {
    play(path);
}

// Or as a preload after a PreloadOutcome::Mismatch:
let skipped = cache.sync(&client, &achievements).await?;
```

`sync` returns the IDs of achievements whose audio the server refused to deliver; a non-empty list means the sync
was partial, so don't persist the new manifest hash and the next preload check will retry.

## NFC reader

The `nfc` feature provides a channel-backed reader handle with cancel-safe waits, suitable for `select!` loops, plus
NDEF text-record parsing. The `nfc-mfrc522` feature adds the built-in backend for MFRC522 modules over SPI (Linux):

```rust
use bloop_client_framework::nfc::{NfcReader, Mfrc522Config};

let reader = NfcReader::spawn_mfrc522(Mfrc522Config::default()).await?;

let uid = reader.wait_for_card().await?;
let achievements = client.bloop(uid).await?;
reader.wait_for_removal().await?;
```

Custom or emulated backends serve the other end of `NfcReader::channel()` instead, and `serve_mfrc522` runs the
built-in backend blocking on the calling thread for applications that supervise reader threads themselves.

## Features

All features are off by default:

```toml
[dependencies]
bloop-client-framework = { version = "1", features = ["audio", "nfc-mfrc522"] }
```

| Feature                   | Description                                                             |
|---------------------------|-------------------------------------------------------------------------|
| `audio`                   | Audio playback for achievement and UI sounds                            |
| `nfc`                     | NFC reader handle, backend channel, and NDEF parsing                    |
| `nfc-mfrc522`             | Built-in MFRC522 reader backend (Linux, SPI + GPIO)                     |
| `tokio-graceful-shutdown` | Implements `IntoSubsystem` for the client, quitting cleanly on shutdown |

## TLS

The server certificate is verified through the operating system's certificate verifier
([rustls-platform-verifier](https://github.com/rustls/rustls-platform-verifier)). On Linux this reads the system CA
bundle once at startup, so locally installed CAs (e.g. for self-signed certificates) require an application restart.
`RootCertSource::DangerousDisabled` skips verification entirely for testing.
