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
#[bloop(opcode = 0x82)]
struct CallPhoneNumber {
    number: String,
    nfc_uid: NfcUid,
}

#[derive(Debug, Encode, Decode, Payload)]
#[bloop(opcode = 0x83)]
struct CallAccepted {
    achievement: AchievementRecord,
}

impl Request for CallPhoneNumber {
    type Response = CallAccepted;
}

// Fully typed request-response:
let accepted = client.custom(CallPhoneNumber { number, nfc_uid }).await?;
```

Protocol errors, including extension-defined codes, arrive as `RequestError::Error(ErrorResponse)`. For exchanges
that fall outside the one-to-one mapping there is `request_raw`.

## On-connect hook

Work that must happen on every (re)connect, such as preloading extension data, runs inside the connection attempt,
before the status flips to `Connected`; a hook failure fails the attempt:

```rust
let builder = builder.on_connect(|session| {
    Box::pin(async move {
        let list = session.custom(PhoneNumberPreload).await?;
        // store the list somewhere shared
        Ok(())
    })
});
```

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
cache.sync(&client, &achievements).await?;
```

## NFC reader

The `nfc` feature provides a channel-backed reader handle with cancel-safe waits, suitable for `select!` loops, plus
NDEF text-record parsing. The `nfc-mfrc522` feature adds the built-in backend for MFRC522 modules over SPI (Linux):

```rust
use bloop_client_framework::nfc::{NfcReader, NfcReaderConfig};

let reader = NfcReader::spawn_mfrc522(NfcReaderConfig::default()).await?;

let uid = reader.wait_for_card().await?;
let achievements = client.bloop(uid).await?;
reader.wait_for_removal().await?;
```

Custom or emulated backends serve the other end of `NfcReader::channel()` instead.

## Features

| Feature | Description |
|---------|-------------|
| `nfc` | NFC reader handle, backend channel, and NDEF parsing |
| `nfc-mfrc522` | Built-in MFRC522 reader backend (Linux, SPI + GPIO) |
| `tokio-graceful-shutdown` | Implements `IntoSubsystem` for the client, quitting cleanly on shutdown |

## TLS

The server certificate is verified against the built-in `webpki-roots` bundle by default; `RootCertSource::Native`
uses the platform store instead, and `RootCertSource::DangerousDisabled` skips verification entirely for testing.
