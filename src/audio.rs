//! Audio playback for achievement and UI sounds.
//!
//! [`play_file`] and [`play_reader`] decode and play a single audio source,
//! returning a [`PlaybackHandle`] that resolves when playback completes and
//! stops the playback when dropped.

use std::fs::File;
use std::future::Future;
use std::io::{BufReader, Read, Seek};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::thread::sleep;
use std::time::Duration;

use rodio::{Decoder, DeviceSinkBuilder, Player};
use thiserror::Error;
use tokio::task::{self, JoinHandle};

/// Errors that can occur during playback.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlaybackError {
    /// Opening the audio source failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The audio output device could not be opened.
    #[error("failed to open audio output: {0}")]
    Output(String),

    /// The audio data could not be decoded.
    #[error("failed to decode audio data")]
    Decode(#[source] rodio::decoder::DecoderError),

    /// The playback task itself failed.
    #[error("playback task failed")]
    Task,
}

/// A running playback.
///
/// Awaiting the handle resolves when the playback completes. Dropping it
/// stops the playback, which makes handles safe to race in `select!` (a
/// dial tone that loses the race falls silent); call
/// [`detach`](Self::detach) to let a playback run to completion in the
/// background instead.
#[derive(Debug)]
pub struct PlaybackHandle {
    join_handle: JoinHandle<Result<(), PlaybackError>>,
    cancelled: Arc<AtomicBool>,
    detached: bool,
}

impl PlaybackHandle {
    /// Lets the playback run to completion in the background.
    pub fn detach(mut self) {
        self.detached = true;
    }
}

impl Future for PlaybackHandle {
    type Output = Result<(), PlaybackError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.join_handle)
            .poll(cx)
            .map(|result| result.unwrap_or(Err(PlaybackError::Task)))
    }
}

impl Drop for PlaybackHandle {
    fn drop(&mut self) {
        if !self.detached {
            self.cancelled.store(true, Ordering::Relaxed);
        }
    }
}

/// Plays an audio file at the given volume.
///
/// Errors, including a missing file, surface when the handle is awaited.
pub fn play_file(path: impl Into<PathBuf>, volume: f32) -> PlaybackHandle {
    let path = path.into();

    play_with(volume, move || Ok(BufReader::new(File::open(path)?)))
}

/// Plays audio from a reader at the given volume.
pub fn play_reader<R>(reader: R, volume: f32) -> PlaybackHandle
where
    R: Read + Seek + Send + Sync + 'static,
{
    play_with(volume, move || Ok(reader))
}

fn play_with<R>(
    volume: f32,
    open: impl FnOnce() -> Result<R, PlaybackError> + Send + 'static,
) -> PlaybackHandle
where
    R: Read + Seek + Send + Sync + 'static,
{
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_flag = cancelled.clone();

    let join_handle = task::spawn_blocking(move || {
        // A handle dropped before the blocking pool got to us (e.g. a lost
        // select! race) should not open the device and emit a stray blip.
        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(());
        }

        // A fresh output stream per playback: a long-lived ALSA stream
        // accumulates underruns while idle and eventually starts crackling,
        // especially on Pi-class hardware. The per-playback overhead is not
        // noticeable, even on a Raspberry Pi Zero.
        //
        // See: https://github.com/RustAudio/rodio/issues/448
        let device_sink = DeviceSinkBuilder::open_default_sink()
            .map_err(|error| PlaybackError::Output(error.to_string()))?;

        let player = Player::connect_new(device_sink.mixer());
        player.set_volume(volume);
        let source = Decoder::new(open()?).map_err(PlaybackError::Decode)?;

        if cancel_flag.load(Ordering::Relaxed) {
            return Ok(());
        }

        player.append(source);

        while !player.empty() {
            sleep(Duration::from_millis(50));

            if cancel_flag.load(Ordering::Relaxed) {
                return Ok(());
            }
        }

        Ok(())
    });

    PlaybackHandle {
        join_handle,
        cancelled,
        detached: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The test environment has no audio device, so the happy path is not
    // testable here; these tests pin the error and cancellation plumbing.

    #[tokio::test]
    async fn missing_file_surfaces_as_error() {
        let error = play_file("/nonexistent/audio.mp3", 1.0).await.unwrap_err();

        assert!(matches!(
            error,
            PlaybackError::Io(_) | PlaybackError::Output(_)
        ));
    }

    #[tokio::test]
    async fn dropping_and_detaching_do_not_panic() {
        drop(play_file("/nonexistent/audio.mp3", 1.0));
        play_file("/nonexistent/audio.mp3", 1.0).detach();

        tokio::task::yield_now().await;
    }
}
