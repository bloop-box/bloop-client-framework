//! Disk caching for achievement audio files.

use std::collections::HashSet;
use std::path::PathBuf;

use bloop_protocol::message::AchievementRecord;
use thiserror::Error;
use tokio::fs;
use tracing::warn;

use crate::client::BloopClient;
use crate::request::RequestError;

/// Errors that can occur while maintaining the audio cache.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AudioCacheError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

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
        // The simple (32-hex) UUID form matches the file names both existing
        // clients wrote, keeping deployed caches valid across the migration.
        record.audio_hash.as_ref().map(|hash| {
            self.base_path
                .join(format!("{}-{}.mp3", record.id.as_simple(), hash))
        })
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
        client: &BloopClient,
        record: &AchievementRecord,
    ) -> Result<Option<PathBuf>, AudioCacheError> {
        let Some(path) = self.path_for(record) else {
            return Ok(None);
        };

        if fs::try_exists(&path).await? {
            return Ok(Some(path));
        }

        fs::create_dir_all(&self.base_path).await?;

        let data = client.retrieve_audio(record.id).await?;

        // Write-then-rename keeps a crash mid-download from leaving a
        // truncated file under the final name, which the existence check
        // would treat as cached forever.
        let temp_path = self
            .base_path
            .join(format!("{}.download", record.id.as_simple()));
        fs::write(&temp_path, data).await?;
        fs::rename(&temp_path, &path).await?;

        Ok(Some(path))
    }

    /// Brings the cache in line with a full list of achievement records.
    ///
    /// Downloads missing audio files and removes cached `.mp3` files no
    /// record refers to anymore. Records whose download the server refuses
    /// (e.g. audio gone missing server-side) are skipped with a warning, so
    /// one broken asset does not stall the rest of the preload; their IDs are
    /// returned so callers can treat the sync as partial, e.g. by not
    /// persisting the audio manifest hash.
    ///
    /// # Errors
    ///
    /// Returns any I/O error, and transport-level [`RequestError`]s
    /// ([`Disconnected`](RequestError::Disconnected) and
    /// [`Shutdown`](RequestError::Shutdown)).
    pub async fn sync(
        &self,
        client: &BloopClient,
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

            if path.extension().is_some_and(|extension| extension == "mp3")
                && !expected.contains(&path)
            {
                let _ = fs::remove_file(&path).await;
            }
        }

        let mut skipped = Vec::new();

        for record in records {
            match self.ensure(client, record).await {
                Ok(_) => {}
                Err(AudioCacheError::Request(RequestError::Error(error))) => {
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
