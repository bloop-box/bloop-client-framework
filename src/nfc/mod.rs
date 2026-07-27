//! NFC reader support.
//!
//! [`NfcReader`] is a channel-backed handle to a reader backend. The built-in
//! MFRC522 backend (feature `nfc-mfrc522`) drives the common SPI reader
//! module; custom backends, including emulated ones, serve the
//! [`NfcReaderBackend`] end of [`NfcReader::channel`] instead.
//!
//! All waiting methods are cancel-safe: dropping the returned future abandons
//! the wait, which backends observe through the closed response channel.

#[cfg(feature = "nfc-mfrc522")]
mod mfrc522;
mod ndef;

#[cfg(feature = "nfc-mfrc522")]
pub use mfrc522::{Mfrc522InitError, NfcReaderConfig};
pub use ndef::{NdefError, NdefMessageParser, NdefTextRecord, parse_ndef_text_record};

use bloop_protocol::NfcUid;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Errors that can occur while talking to the reader backend.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NfcReaderError {
    /// The reader backend is no longer running.
    #[error("the NFC reader backend is no longer running")]
    Disconnected,

    /// Reading or parsing the tag's NDEF data failed.
    #[error("failed to read NDEF text record: {0}")]
    Read(String),
}

/// A request served by an NFC reader backend.
#[derive(Debug)]
pub enum NfcReaderRequest {
    /// Polls until a card is present, answering with its UID.
    ///
    /// Abandoned when the response sender closes.
    WaitForCard(oneshot::Sender<NfcUid>),

    /// Polls until the present card is gone.
    ///
    /// Abandoned when the response sender closes.
    WaitForRemoval(oneshot::Sender<()>),

    /// Reads the tag's NDEF text record; errors travel as strings.
    ReadNdefText(oneshot::Sender<Result<String, String>>),
}

/// The receiving end a reader backend serves.
pub type NfcReaderBackend = mpsc::Receiver<NfcReaderRequest>;

/// Handle to an NFC reader backend.
#[derive(Clone, Debug)]
pub struct NfcReader {
    tx: mpsc::Sender<NfcReaderRequest>,
}

impl NfcReader {
    /// Creates a handle together with the backend end serving it.
    pub fn channel() -> (Self, NfcReaderBackend) {
        let (tx, rx) = mpsc::channel(4);
        (Self { tx }, rx)
    }

    /// Spawns the built-in MFRC522 backend on a dedicated thread.
    ///
    /// # Errors
    ///
    /// Returns an [`Mfrc522InitError`] if the SPI device, the GPIO reset
    /// line, or the chip itself fails to initialize.
    #[cfg(feature = "nfc-mfrc522")]
    pub async fn spawn_mfrc522(config: NfcReaderConfig) -> Result<Self, Mfrc522InitError> {
        let (reader, backend) = Self::channel();
        mfrc522::spawn(config, backend).await?;

        Ok(reader)
    }

    /// Waits until a card is present, returning its UID.
    ///
    /// Cancel-safe: dropping the future abandons the wait.
    ///
    /// # Errors
    ///
    /// Returns [`NfcReaderError::Disconnected`] if the backend is gone.
    pub async fn wait_for_card(&self) -> Result<NfcUid, NfcReaderError> {
        self.roundtrip(NfcReaderRequest::WaitForCard).await
    }

    /// Waits until the present card is removed.
    ///
    /// Cancel-safe: dropping the future abandons the wait.
    ///
    /// # Errors
    ///
    /// Returns [`NfcReaderError::Disconnected`] if the backend is gone.
    pub async fn wait_for_removal(&self) -> Result<(), NfcReaderError> {
        self.roundtrip(NfcReaderRequest::WaitForRemoval).await
    }

    /// Reads the present tag's NDEF text record.
    ///
    /// # Errors
    ///
    /// Returns [`NfcReaderError::Read`] if the tag carries no readable text
    /// record, or [`NfcReaderError::Disconnected`] if the backend is gone.
    pub async fn read_ndef_text(&self) -> Result<String, NfcReaderError> {
        self.roundtrip(NfcReaderRequest::ReadNdefText)
            .await?
            .map_err(NfcReaderError::Read)
    }

    async fn roundtrip<T>(
        &self,
        request: impl FnOnce(oneshot::Sender<T>) -> NfcReaderRequest,
    ) -> Result<T, NfcReaderError> {
        let (response_tx, response_rx) = oneshot::channel();

        self.tx
            .send(request(response_tx))
            .await
            .map_err(|_| NfcReaderError::Disconnected)?;

        response_rx.await.map_err(|_| NfcReaderError::Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn requests_round_trip_through_a_backend() {
        let (reader, mut backend) = NfcReader::channel();
        let uid = NfcUid::try_from(&[1u8, 2, 3, 4][..]).unwrap();

        tokio::spawn(async move {
            while let Some(request) = backend.recv().await {
                match request {
                    NfcReaderRequest::WaitForCard(response) => {
                        let _ = response.send(uid);
                    }
                    NfcReaderRequest::WaitForRemoval(response) => {
                        let _ = response.send(());
                    }
                    NfcReaderRequest::ReadNdefText(response) => {
                        let _ = response.send(Ok("hello".to_string()));
                    }
                }
            }
        });

        assert_eq!(reader.wait_for_card().await.unwrap(), uid);
        reader.wait_for_removal().await.unwrap();
        assert_eq!(reader.read_ndef_text().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn dropped_wait_shows_as_closed_response() {
        let (reader, mut backend) = NfcReader::channel();

        let wait = reader.wait_for_card();
        drop(wait);

        // The handle never sent anything, so the backend sees nothing; a
        // cancelled in-flight wait instead arrives with a closed sender.
        let in_flight = tokio::spawn(async move { reader.wait_for_card().await });

        let request = backend.recv().await.unwrap();
        let NfcReaderRequest::WaitForCard(mut response) = request else {
            panic!("unexpected request");
        };

        in_flight.abort();
        response.closed().await;
        assert!(response.is_closed());
    }

    #[tokio::test]
    async fn gone_backend_reports_disconnected() {
        let (reader, backend) = NfcReader::channel();
        drop(backend);

        assert!(matches!(
            reader.wait_for_card().await,
            Err(NfcReaderError::Disconnected)
        ));
    }
}
