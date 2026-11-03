//! The statistics saved to `<state.dir>/stats.json` (counters, hourly history, the three top
//! lists and the upstream tallies; never the query log or device names). The file is written
//! whole, through a `.part` file and a rename, at most once an hour and only when its bytes
//! differ from the last ones written or loaded, then once more on a clean stop and when the
//! user clears the statistics.
//!
//! A missing, damaged, too large or other-version file never stops picoguard: it starts with
//! empty statistics, logs why, and leaves the file as it is until the next save replaces it.

use std::fs::File;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::atomic;
use crate::pipeline::Pipeline;
use crate::stats::Counters;

pub const FILE_NAME: &str = "stats.json";
pub const SAVE_INTERVAL: Duration = Duration::from_secs(3_600);

/// Far above the largest file a save writes: with `top_k` at its limit of 1,000 and the
/// longest names, two hex-coded name lists, the clients and a 90-day history take about 1.4 MB.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// The file's content. Fields unknown to this version are ignored when a file is read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SavedStats {
    pub version: u32,
    pub since: u64,
    pub counters: Counters,
    /// Hour number (hours since the epoch), queries and blocked queries; the hours that have any.
    pub hours: Vec<(u64, u64, u64)>,
    /// A name as its wire bytes in lowercase hex, its count and its error bound.
    pub top_queried: Vec<(String, u64, u64)>,
    pub top_blocked: Vec<(String, u64, u64)>,
    pub top_clients: Vec<(IpAddr, u64, u64)>,
    pub upstreams: Vec<SavedUpstream>,
}

impl SavedStats {
    pub const VERSION: u32 = 1;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedUpstream {
    pub label: String,
    pub answered: u64,
    pub failed: u64,
    pub answer_micros: u64,
}

#[derive(Deserialize)]
struct Header {
    version: u32,
}

/// How saving is going, for the status page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SaveStatus {
    pub enabled: bool,
    /// Unix seconds of the last save that wrote the file.
    pub last_saved: Option<u64>,
    /// Why the last save failed, until one works.
    pub error: Option<String>,
}

struct Written {
    /// The hash of the bytes last written or loaded.
    hash: Option<u64>,
    last_saved: Option<u64>,
    error: Option<String>,
}

pub struct StatsSaver {
    /// `None` with `[stats] persist = false`: the file is never read or written.
    dir: Option<PathBuf>,
    written: Mutex<Written>,
    /// Two saves never run together: they would write the same `.part` file.
    saving: tokio::sync::Mutex<()>,
}

impl StatsSaver {
    pub fn open(dir: PathBuf) -> StatsSaver {
        StatsSaver::new(Some(dir))
    }

    /// `[stats] persist = false`.
    pub fn disabled() -> StatsSaver {
        StatsSaver::new(None)
    }

    fn new(dir: Option<PathBuf>) -> StatsSaver {
        StatsSaver {
            dir,
            written: Mutex::new(Written {
                hash: None,
                last_saved: None,
                error: None,
            }),
            saving: tokio::sync::Mutex::new(()),
        }
    }

    pub fn status(&self) -> SaveStatus {
        let written = self.written.lock().unwrap();

        SaveStatus {
            enabled: self.dir.is_some(),
            last_saved: written.last_saved,
            error: written.error.clone(),
        }
    }

    /// Puts the saved file's statistics in `pipeline`, once at start before serving. Whatever
    /// is wrong with the file is logged and the statistics start empty.
    pub fn load(&self, pipeline: &Pipeline) {
        let Some(dir) = &self.dir else {
            return;
        };

        let path = dir.join(FILE_NAME);
        match read(&path) {
            Ok(Some(saved)) => pipeline.restore_stats(&saved),

            Ok(None) => {}

            Err(reason) => {
                log::warn!(
                    "starting with empty statistics: {}: {reason}",
                    path.display()
                );
            }
        }

        // The next save writes when something differs from now, not from what the file held.
        if let Ok(bytes) = encode(&pipeline.saved_stats()) {
            self.written.lock().unwrap().hash = Some(xxh3_64(&bytes));
        }
    }

    /// Writes the file unless the statistics are as they were at the last write or load, and
    /// returns whether it wrote. A failure is logged, kept for the status page and returned;
    /// the next call tries again.
    pub async fn save_if_changed(&self, pipeline: &Arc<Pipeline>) -> io::Result<bool> {
        let Some(dir) = self.dir.clone() else {
            return Ok(false);
        };

        let _one_at_a_time = self.saving.lock().await;
        let before = self.written.lock().unwrap().hash;
        let pipeline = Arc::clone(pipeline);
        let outcome = tokio::task::spawn_blocking(move || {
            let bytes = encode(&pipeline.saved_stats())?;
            let hash = xxh3_64(&bytes);
            if Some(hash) == before {
                return Ok(None);
            }

            atomic::write_file(&dir, FILE_NAME, &bytes, None)?;

            Ok(Some(hash))
        })
        .await
        .unwrap_or_else(|_| Err(io::Error::other("the write was stopped")));

        let mut written = self.written.lock().unwrap();
        match outcome {
            Ok(Some(hash)) => {
                written.hash = Some(hash);
                written.last_saved = Some(unix_seconds());
                written.error = None;

                Ok(true)
            }

            Ok(None) => Ok(false),

            Err(error) => {
                log::warn!("cannot save the statistics: {error}");
                written.error = Some(error.to_string());

                Err(error)
            }
        }
    }

    /// Saves every `every` while picoguard runs, for as long as the future is polled.
    pub async fn run(self: Arc<Self>, pipeline: Arc<Pipeline>, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.save_if_changed(&pipeline).await;
        }
    }
}

/// `Ok(None)` when there is no file. An `Err` is the reason a file that is there is not used.
fn read(path: &std::path::Path) -> Result<Option<SavedStats>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };

    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!("the file is larger than {MAX_FILE_BYTES} bytes"));
    }

    let header: Header = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if header.version != SavedStats::VERSION {
        return Err(format!("version {} is not supported", header.version));
    }

    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn encode(saved: &SavedStats) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(saved).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::other("the statistics are too large to save"));
    }

    Ok(bytes)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::Config;
    use crate::dns::wire::Name;
    use crate::policy::Policy;
    use crate::stats::{Event, QueryResult};
    use crate::test_dir::TestDir;

    fn pipeline() -> Arc<Pipeline> {
        let mut config = Config::default();
        config.upstream.servers = vec!["udp://127.0.0.1:9".to_string()];

        Pipeline::new(&config, Arc::new(Policy::new())).unwrap()
    }

    fn record(pipeline: &Pipeline, qname: &str, result: QueryResult) {
        let qname = Name::from_text(qname).unwrap();
        pipeline.stats().record(&Event {
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
            qname: &qname,
            qtype: 1,
            result,
            upstream: None,
            latency: Duration::from_micros(10),
        });
    }

    fn file_in(dir: &TestDir) -> PathBuf {
        dir.path().join(FILE_NAME)
    }

    fn loaded(dir: &TestDir) -> (Arc<StatsSaver>, Arc<Pipeline>) {
        let saver = Arc::new(StatsSaver::open(dir.path().to_path_buf()));
        let pipeline = pipeline();
        saver.load(&pipeline);

        (saver, pipeline)
    }

    #[tokio::test]
    async fn a_fresh_start_with_no_file_writes_nothing_until_something_is_counted() {
        let dir = TestDir::new("stats-fresh");
        let (saver, pipeline) = loaded(&dir);

        assert!(!saver.save_if_changed(&pipeline).await.unwrap());
        assert!(!file_in(&dir).exists());

        record(&pipeline, "example.com", QueryResult::Pass);

        assert!(saver.save_if_changed(&pipeline).await.unwrap());
        assert!(file_in(&dir).exists());
        assert!(!saver.save_if_changed(&pipeline).await.unwrap());
    }

    #[tokio::test]
    async fn the_file_is_whole_for_the_owner_only_and_leaves_no_part() {
        let dir = TestDir::new("stats-file");
        fs::write(dir.path().join("stats.json.part"), "stale").unwrap();
        let (saver, pipeline) = loaded(&dir);
        record(&pipeline, "example.com", QueryResult::Pass);

        saver.save_if_changed(&pipeline).await.unwrap();

        let mode = fs::metadata(file_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.path().join("stats.json.part").exists());
        let saved: SavedStats = serde_json::from_slice(&fs::read(file_in(&dir)).unwrap()).unwrap();
        assert_eq!(saved.version, 1);
        assert_eq!(saved.counters.total, 1);
        assert_eq!(saved.top_queried.len(), 1);
        assert_eq!(saved.hours.len(), 1);
        assert_eq!(saved.top_queried[0].0, "076578616d706c6503636f6d00");
        assert_eq!(saved.top_clients[0].0.to_string(), "192.168.1.7");
    }

    #[tokio::test]
    async fn a_restart_keeps_the_statistics_and_the_next_save_waits_for_a_change() {
        let dir = TestDir::new("stats-restart");
        let (saver, pipeline) = loaded(&dir);
        for _ in 0..3 {
            record(&pipeline, "ads.example", QueryResult::BlockedRequest);
        }

        record(&pipeline, "ok.example", QueryResult::Pass);
        pipeline.stats().record_dropped();
        saver.save_if_changed(&pipeline).await.unwrap();
        let before = pipeline.stats().snapshot();

        let (restarted_saver, restarted) = loaded(&dir);
        let after = restarted.stats().snapshot();

        assert_eq!(after.counters, before.counters);
        assert_eq!(after.since, before.since);
        assert_eq!(after.hourly, before.hourly);
        assert_eq!(after.top_queried, before.top_queried);
        assert_eq!(after.top_blocked, before.top_blocked);
        assert_eq!(after.top_clients, before.top_clients);
        assert!(!restarted_saver.save_if_changed(&restarted).await.unwrap());
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_used_starts_fresh_and_stays_as_it_is_until_a_save() {
        let too_large = format!(
            "{{\"version\":1,\"pad\":\"{}\"}}",
            "x".repeat(3 * 1024 * 1024)
        );
        let cases = [
            ("broken", "{\"version\":1,".to_string()),
            ("not-json", "just text".to_string()),
            ("empty", String::new()),
            ("other-version", "{\"version\":2,\"since\":5}".to_string()),
            ("wrong-shape", "{\"version\":1,\"counters\":7}".to_string()),
            ("oversized", too_large),
        ];

        for (name, text) in cases {
            let dir = TestDir::new(&format!("stats-{name}"));
            fs::write(file_in(&dir), &text).unwrap();

            let (saver, pipeline) = loaded(&dir);

            assert_eq!(pipeline.stats().snapshot().counters.total, 0, "{name}");
            assert!(!saver.save_if_changed(&pipeline).await.unwrap(), "{name}");
            assert_eq!(fs::read_to_string(file_in(&dir)).unwrap(), text, "{name}");

            record(&pipeline, "example.com", QueryResult::Pass);
            assert!(saver.save_if_changed(&pipeline).await.unwrap(), "{name}");
            let (_, restarted) = loaded(&dir);
            assert_eq!(restarted.stats().snapshot().counters.total, 1, "{name}");
        }
    }

    #[tokio::test]
    async fn a_file_with_fields_this_build_does_not_know_is_still_read() {
        let dir = TestDir::new("stats-extra");
        let (saver, pipeline) = loaded(&dir);
        record(&pipeline, "example.com", QueryResult::Pass);
        saver.save_if_changed(&pipeline).await.unwrap();
        let text = fs::read_to_string(file_in(&dir)).unwrap();
        fs::write(
            file_in(&dir),
            text.replacen("{\"version\":1", "{\"version\":1,\"note\":[1,2]", 1),
        )
        .unwrap();

        let (_, restarted) = loaded(&dir);

        assert_eq!(restarted.stats().snapshot().counters.total, 1);
    }

    #[tokio::test]
    async fn with_saving_off_nothing_is_read_or_written() {
        let dir = TestDir::new("stats-off");
        let (saver, pipeline) = loaded(&dir);
        record(&pipeline, "example.com", QueryResult::Pass);
        saver.save_if_changed(&pipeline).await.unwrap();
        let before = fs::read(file_in(&dir)).unwrap();

        let off = StatsSaver::disabled();
        let fresh = self::pipeline();
        off.load(&fresh);
        record(&fresh, "other.example", QueryResult::Pass);
        record(&fresh, "other.example", QueryResult::Pass);

        assert_eq!(fresh.stats().snapshot().counters.total, 2);
        assert!(!off.save_if_changed(&fresh).await.unwrap());
        assert_eq!(fs::read(file_in(&dir)).unwrap(), before);
        assert_eq!(
            off.status(),
            SaveStatus {
                enabled: false,
                last_saved: None,
                error: None
            }
        );
    }

    #[tokio::test]
    async fn a_failed_save_is_reported_and_tried_again() {
        let dir = TestDir::new("stats-failing");
        let missing = dir.path().join("missing");
        let saver = StatsSaver::open(missing.clone());
        let pipeline = pipeline();
        saver.load(&pipeline);
        record(&pipeline, "example.com", QueryResult::Pass);

        assert!(saver.save_if_changed(&pipeline).await.is_err());
        let status = saver.status();
        assert!(status.enabled);
        assert_eq!(status.last_saved, None);
        assert!(status.error.is_some());

        fs::create_dir(&missing).unwrap();

        assert!(saver.save_if_changed(&pipeline).await.unwrap());
        let status = saver.status();
        assert!(status.last_saved.is_some());
        assert_eq!(status.error, None);
    }

    #[tokio::test]
    async fn a_clear_is_a_change_that_gets_saved() {
        let dir = TestDir::new("stats-clear");
        let (saver, pipeline) = loaded(&dir);
        record(&pipeline, "example.com", QueryResult::Pass);
        saver.save_if_changed(&pipeline).await.unwrap();

        pipeline.clear_stats();

        assert!(saver.save_if_changed(&pipeline).await.unwrap());
        let (_, restarted) = loaded(&dir);
        assert_eq!(restarted.stats().snapshot().counters.total, 0);
        assert!(restarted.stats().snapshot().top_queried.is_empty());
    }

    #[tokio::test]
    async fn the_hourly_task_writes_only_when_something_changed() {
        let dir = TestDir::new("stats-hourly");
        let (saver, pipeline) = loaded(&dir);
        let every = Duration::from_millis(40);
        let task = tokio::spawn(Arc::clone(&saver).run(Arc::clone(&pipeline), every));

        tokio::time::sleep(every * 4).await;
        assert!(!file_in(&dir).exists(), "nothing counted, nothing written");

        record(&pipeline, "example.com", QueryResult::Pass);
        tokio::time::sleep(every * 4).await;
        assert!(file_in(&dir).exists());
        let written = saver.status().last_saved;
        let modified = fs::metadata(file_in(&dir)).unwrap().modified().unwrap();

        tokio::time::sleep(every * 4).await;
        assert_eq!(saver.status().last_saved, written);
        assert_eq!(
            fs::metadata(file_in(&dir)).unwrap().modified().unwrap(),
            modified
        );
        task.abort();
    }
}
