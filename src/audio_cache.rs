//! Disk caching for achievement audio files.

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use bloop_protocol::message::AchievementRecord;
use thiserror::Error;
use tokio::fs;
use tracing::warn;
use uuid::Uuid;

use crate::client::BloopClient;
use crate::connection::Session;
use crate::request::RequestError;

/// A source of achievement audio data.
///
/// Implemented for [`&BloopClient`](BloopClient) and
/// [`&mut Session`](Session), so the cache works both in normal operation
/// and inside an on-connect hook. Inside the hook you must pass the
/// [`Session`]: calling [`BloopClient`] methods there deadlocks the client
/// (see [`on_connect`](crate::BloopClientBuilder::on_connect)).
pub trait AudioProvider {
    /// Requests the audio data for an achievement.
    fn retrieve_audio(
        &mut self,
        achievement_id: Uuid,
    ) -> impl Future<Output = Result<Vec<u8>, RequestError>> + Send;
}

impl AudioProvider for &BloopClient {
    async fn retrieve_audio(&mut self, achievement_id: Uuid) -> Result<Vec<u8>, RequestError> {
        BloopClient::retrieve_audio(self, achievement_id).await
    }
}

impl AudioProvider for &mut Session<'_> {
    async fn retrieve_audio(&mut self, achievement_id: Uuid) -> Result<Vec<u8>, RequestError> {
        Session::retrieve_audio(self, achievement_id).await
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors that can occur while maintaining the audio cache.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AudioCacheError {
    /// Reading or writing the cache directory failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Downloading audio data from the server failed.
    #[error(transparent)]
    Request(#[from] RequestError),
}

/// A disk cache for achievement audio files.
///
/// File names embed both the achievement ID and the audio hash, so
/// server-side audio updates change the file name and naturally invalidate
/// stale entries; [`sync`](Self::sync) removes them.
#[derive(Clone, Debug)]
pub struct AudioCache {
    base_path: PathBuf,
}

impl AudioCache {
    /// Creates a cache rooted at the given directory.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }

    /// Returns the cache path for a record's audio file.
    ///
    /// Returns `None` when the achievement has no audio.
    pub fn path_for(&self, record: &AchievementRecord) -> Option<PathBuf> {
        record
            .audio_hash
            .as_ref()
            .map(|hash| self.base_path.join(format!("{}_{}.mp3", record.id, hash)))
    }

    /// Ensures a record's audio file is cached, downloading it if missing.
    ///
    /// Returns the cached file's path, or `None` when the achievement has no
    /// audio.
    ///
    /// # Errors
    ///
    /// Returns any I/O error, and any [`RequestError`] from the download.
    pub async fn ensure(
        &self,
        mut provider: impl AudioProvider,
        record: &AchievementRecord,
    ) -> Result<Option<PathBuf>, AudioCacheError> {
        self.ensure_inner(&mut provider, record).await
    }

    async fn ensure_inner<P: AudioProvider>(
        &self,
        provider: &mut P,
        record: &AchievementRecord,
    ) -> Result<Option<PathBuf>, AudioCacheError> {
        let Some(path) = self.path_for(record) else {
            return Ok(None);
        };

        if fs::try_exists(&path).await? {
            return Ok(Some(path));
        }

        fs::create_dir_all(&self.base_path).await?;

        let data = provider.retrieve_audio(record.id).await?;

        // Write-then-rename keeps a crash mid-download from leaving a
        // truncated file under the final name, which the existence check
        // would treat as cached forever. The unique suffix keeps concurrent
        // downloads of the same record from interleaving into one file.
        let temp_path = self.base_path.join(format!(
            "{}.{}.download",
            record.id,
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&temp_path, data).await?;
        fs::rename(&temp_path, &path).await?;

        Ok(Some(path))
    }

    /// Brings the cache in line with a full list of achievement records.
    ///
    /// Downloads missing audio files and removes cached `.mp3` files no
    /// record refers to anymore, along with `.download` leftovers from
    /// interrupted downloads. Records whose download the server refuses
    /// (e.g. audio gone missing server-side) are skipped with a warning, so
    /// one broken asset does not stall the rest of the preload; their IDs are
    /// returned so callers can treat the sync as partial, e.g. by not
    /// persisting the audio manifest hash.
    ///
    /// A `sync` racing a concurrent [`ensure`](Self::ensure) on another task
    /// may prune the in-flight temp file and fail that `ensure`; the cache
    /// is designed for use from a single task.
    ///
    /// # Errors
    ///
    /// Returns any I/O error. Every [`RequestError`] other than the
    /// server-refusal [`Error`](RequestError::Error) case propagates too:
    /// transport loss ([`Disconnected`](RequestError::Disconnected),
    /// [`Shutdown`](RequestError::Shutdown)) as well as malformed or
    /// unexpected responses.
    pub async fn sync(
        &self,
        mut provider: impl AudioProvider,
        records: &[AchievementRecord],
    ) -> Result<Vec<uuid::Uuid>, AudioCacheError> {
        fs::create_dir_all(&self.base_path).await?;

        let expected: HashSet<PathBuf> = records
            .iter()
            .filter_map(|record| self.path_for(record))
            .collect();

        let mut entries = fs::read_dir(&self.base_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            let is_stale_audio = path.extension().is_some_and(|extension| extension == "mp3")
                && !expected.contains(&path);
            let is_leftover_download = path
                .extension()
                .is_some_and(|extension| extension == "download");

            if is_stale_audio || is_leftover_download {
                let _ = fs::remove_file(&path).await;
            }
        }

        let mut skipped = Vec::new();

        for record in records {
            match self.ensure_inner(&mut provider, record).await {
                Ok(_) => {}
                // A fatal error means the server closed the connection; that
                // is a failed sync, not a skippable record.
                Err(AudioCacheError::Request(RequestError::Error(error))) if !error.is_fatal() => {
                    warn!(
                        "skipping audio for achievement {}: server answered {:?}",
                        record.id, error
                    );
                    skipped.push(record.id);
                }
                Err(error) => return Err(error),
            }
        }

        Ok(skipped)
    }
}
