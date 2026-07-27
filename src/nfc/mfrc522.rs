//! The built-in MFRC522 reader backend.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use bloop_protocol::NfcUid;
use gpiocdev::Request;
use gpiocdev::line::Value;
use linux_embedded_hal::SpidevDevice;
use linux_embedded_hal::spidev::{SpiModeFlags, Spidev, SpidevOptions};
use mfrc522::comm::Interface;
use mfrc522::comm::blocking::spi::{DummyDelay, SpiInterface};
use mfrc522::{Initialized, Mfrc522, Uid};
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{instrument, warn};

use super::{NfcReaderBackend, NfcReaderRequest};
use crate::nfc::ndef::{NdefMessageParser, parse_ndef_text_record};

/// Errors that can occur while initializing the MFRC522 backend.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Mfrc522InitError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The GPIO reset line could not be driven.
    #[error("failed to drive the GPIO reset line: {0}")]
    Gpio(String),

    /// The MFRC522 chip failed to initialize.
    #[error("failed to initialize the MFRC522: {0}")]
    Chip(String),
}

/// Hardware wiring of the MFRC522 reader.
#[derive(Clone, Debug)]
pub struct NfcReaderConfig {
    pub spi_dev_path: PathBuf,
    pub gpio_dev_path: PathBuf,
    pub reset_pin_line: u32,
}

impl Default for NfcReaderConfig {
    fn default() -> Self {
        Self {
            spi_dev_path: "/dev/spidev0.0".into(),
            gpio_dev_path: "/dev/gpiochip0".into(),
            reset_pin_line: 25,
        }
    }
}

/// Serves the backend on the calling thread, returning on channel close.
///
/// The blocking sibling of [`NfcReader::spawn_mfrc522`], for applications
/// that manage reader threads themselves (e.g. under a thread supervisor).
///
/// # Errors
///
/// Returns an [`Mfrc522InitError`] if the hardware fails to initialize.
///
/// [`NfcReader::spawn_mfrc522`]: super::NfcReader::spawn_mfrc522
pub fn serve_blocking(
    config: NfcReaderConfig,
    backend: NfcReaderBackend,
) -> Result<(), Mfrc522InitError> {
    let (adapter, reset_line) = init(config)?;
    serve(adapter, reset_line, backend);

    Ok(())
}

/// Spawns the backend thread, awaiting its hardware initialization.
pub(super) async fn spawn(
    config: NfcReaderConfig,
    backend: NfcReaderBackend,
) -> Result<(), Mfrc522InitError> {
    let (init_tx, init_rx) = oneshot::channel();

    std::thread::Builder::new()
        .name("nfc-reader".to_string())
        .spawn(move || run(config, backend, init_tx))?;

    init_rx.await.unwrap_or_else(|_| {
        Err(Mfrc522InitError::Chip(
            "reader thread died during initialization".to_string(),
        ))
    })
}

#[instrument(skip(backend, init_tx))]
fn run(
    config: NfcReaderConfig,
    backend: NfcReaderBackend,
    init_tx: oneshot::Sender<Result<(), Mfrc522InitError>>,
) {
    let (adapter, reset_line) = match init(config) {
        Ok(initialized) => {
            let _ = init_tx.send(Ok(()));
            initialized
        }
        Err(error) => {
            let _ = init_tx.send(Err(error));
            return;
        }
    };

    serve(adapter, reset_line, backend);
}

// The GPIO request must stay alive for the reader's lifetime; releasing it
// would let the reset line float.
fn serve(mut adapter: InitializedAdapter, _reset_line: Request, mut backend: NfcReaderBackend) {
    'main_loop: while let Some(request) = backend.blocking_recv() {
        match request {
            NfcReaderRequest::WaitForCard(response) => {
                let uid = loop {
                    if response.is_closed() {
                        continue 'main_loop;
                    }

                    if let Some(uid) = adapter.select_target() {
                        break uid;
                    }

                    sleep(Duration::from_millis(50));
                };

                let _ = response.send(uid);
            }

            NfcReaderRequest::WaitForRemoval(response) => {
                loop {
                    if response.is_closed() {
                        continue 'main_loop;
                    }

                    if adapter.check_for_release() {
                        break;
                    }

                    sleep(Duration::from_millis(50));
                }

                let _ = response.send(());
            }

            NfcReaderRequest::ReadNdefText(response) => {
                let result = adapter.read_ndef_text();

                if let Err(reason) = &result {
                    warn!("failed to read tag data: {}", reason);
                }

                let _ = response.send(result);
            }
        }
    }
}

type InitializedAdapter = Adapter<SpiInterface<SpidevDevice, DummyDelay>>;

fn init(config: NfcReaderConfig) -> Result<(InitializedAdapter, Request), Mfrc522InitError> {
    let options = SpidevOptions::new()
        .max_speed_hz(1_000_000)
        .mode(SpiModeFlags::SPI_MODE_0)
        .build();

    let mut spi = Spidev::open(config.spi_dev_path)?;
    spi.configure(&options)?;

    let reset_line = Request::builder()
        .on_chip(config.gpio_dev_path)
        .with_consumer("bloop-client-framework")
        .with_line(config.reset_pin_line)
        .as_output(Value::Inactive)
        .request()
        .map_err(|error| Mfrc522InitError::Gpio(error.to_string()))?;

    sleep(Duration::from_millis(150));
    reset_line
        .set_lone_value(Value::Active)
        .map_err(|error| Mfrc522InitError::Gpio(error.to_string()))?;
    sleep(Duration::from_millis(50));

    let interface = SpiInterface::new(SpidevDevice(spi));
    let mfrc522 = Mfrc522::new(interface)
        .init()
        .map_err(|error| Mfrc522InitError::Chip(format!("{error:?}")))?;

    Ok((Adapter { mfrc522 }, reset_line))
}

struct Adapter<COMM: Interface> {
    mfrc522: Mfrc522<COMM, Initialized>,
}

impl<E, COMM: Interface<Error = E>> Adapter<COMM> {
    fn select_target(&mut self) -> Option<NfcUid> {
        let atqa = self.mfrc522.reqa().ok()?;
        let uid = self.mfrc522.select(&atqa).ok()?;

        Some(nfc_uid_from_mfrc522(uid))
    }

    fn check_for_release(&mut self) -> bool {
        // For some bizarre reason, the MFRC522 chip switches between found
        // and not found state, so we have to check twice. This is documented
        // in multiple issues of several libraries.
        //
        // See: https://github.com/pimylifeup/MFRC522-python/issues/15#issuecomment-511671924
        if self.mfrc522.wupa().is_ok() {
            return false;
        }

        match self.mfrc522.wupa() {
            Ok(_) => false,
            Err(error) => !matches!(error, mfrc522::Error::Collision),
        }
    }

    fn read_ndef_text(&mut self) -> Result<String, String> {
        let mut parser = NdefMessageParser::new();

        let capabilities = self
            .mfrc522
            .mf_read(3)
            .map_err(|_| "failed to read capability container".to_string())?;

        let total_bytes = (capabilities[2] as usize) * 8;
        let total_pages = total_bytes / 4;
        let total_quads = (total_pages / 4) as u8;

        for quad in 1..total_quads + 1 {
            let quad_data = self
                .mfrc522
                .mf_read(4 * quad)
                .map_err(|_| format!("failed to read block {}", 4 * quad))?;
            parser.add_data(&quad_data);

            if parser.is_done() {
                break;
            }

            if quad == 2 && !parser.has_started() {
                return Err("no NDEF message found in first sector".to_string());
            }
        }

        if !parser.is_done() {
            return Err("NDEF message incomplete".to_string());
        }

        let record = parse_ndef_text_record(parser.data()).map_err(|error| error.to_string())?;
        record.text().map_err(|error| error.to_string())
    }
}

fn nfc_uid_from_mfrc522(uid: Uid) -> NfcUid {
    NfcUid::try_from(uid.as_bytes()).expect("MFRC522 UIDs come in standard lengths")
}
