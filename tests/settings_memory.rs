//! What the saved settings cost once loaded: the config file kept beside them (what they go
//! over), the settings themselves and the page rules, which were in memory before they were
//! saved too. Reading the file peaks at its size a few times and then gives it back. This
//! test binary has a counting global allocator and a single test, so nothing else allocates
//! while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use picoguard::config::Config;
use picoguard::scheduler::{Action, ButtonRule, MAX_BUTTON_RULES};
use picoguard::settings::{self, CacheSettings, Settings, UpstreamSettings};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grow(layout.size());

        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grow(new_size);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);

        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The config file kept beside the settings, the path and the lock, for the default config.
/// Measured: 1,506 bytes.
const KEPT_CONFIG_BYTES: usize = 4 * 1024;

/// One saved page rule: its entry and its name. Measured: 54 bytes for the names below.
const PER_RULE_BYTES: usize = 96;

/// The other settings of the file below. Measured: 105 bytes.
const OTHER_SETTINGS_BYTES: usize = 1024;

/// Reading the file: its bytes, then the parsed settings beside them, and a merged config.
/// Measured: 1.9 times the file on top of what the load keeps.
const READ_PEAK_FILES: usize = 3;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn reset_peak() -> usize {
    let live = live();
    PEAK.store(live, Ordering::Relaxed);

    live
}

fn peak_since(before: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(before)
}

fn write_config(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("picoguard.toml");
    std::fs::write(&path, format!("[state]\ndir = {dir:?}\n")).unwrap();

    path
}

/// The state that stays after a load: what `load` returns but the config in force.
fn kept_after_load(config_path: &Path) -> usize {
    let before = live();
    let loaded = settings::load(config_path).unwrap();
    assert_eq!(loaded.saved.error(), None);
    drop(loaded.config);
    let kept = live() - before;
    drop(loaded.saved);

    kept
}

#[test]
fn the_loaded_settings_cost_the_config_file_and_their_own_bytes() {
    let dir =
        std::env::temp_dir().join(format!("picoguard-settings-memory-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = write_config(&dir);
    // Warms what the first load allocates once: the TLS roots behind the upstream check.
    drop(settings::load(&config_path).unwrap());

    let without_file = kept_after_load(&config_path);
    assert!(
        without_file <= KEPT_CONFIG_BYTES,
        "with no settings file the load keeps {without_file} bytes"
    );

    let file = Settings {
        upstream: Some(UpstreamSettings {
            servers: vec![
                "https://9.9.9.9/dns-query".to_string(),
                "tls://1.1.1.1#cloudflare-dns.com".to_string(),
            ],
            bootstrap: vec!["9.9.9.9".parse().unwrap()],
        }),
        cache: Some(CacheSettings {
            max_entries: 20_000,
            max_bytes: 8 * 1024 * 1024,
            min_ttl: 60,
            max_ttl: 86_400,
            optimistic: true,
        }),
        safe_search: Some(true),
        page_rules: (0..MAX_BUTTON_RULES)
            .map(|number| ButtonRule {
                name: format!("page-rule-{number:03}.example"),
                action: Action::Block,
            })
            .collect(),
        ..Settings::default()
    };
    let text = serde_json::to_string_pretty(&file).unwrap();
    std::fs::write(dir.join(settings::FILE_NAME), &text).unwrap();
    drop(file);

    let before = reset_peak();
    let with_file = kept_after_load(&config_path);
    let peak = peak_since(before);

    let settings_bytes = with_file - without_file;
    println!(
        "without a file {without_file}, with a file of {} bytes {with_file} \
         ({settings_bytes} for the settings, {} per rule), peak {peak}",
        text.len(),
        settings_bytes / MAX_BUTTON_RULES
    );
    assert!(
        settings_bytes <= MAX_BUTTON_RULES * PER_RULE_BYTES + OTHER_SETTINGS_BYTES,
        "the settings of {} rules keep {settings_bytes} bytes",
        MAX_BUTTON_RULES
    );

    // The config in force is a copy of the file's that the server needs anyway.
    let config_in_force = {
        let before = live();
        let config = Config::default();
        let bytes = live() - before;
        drop(config);

        bytes
    };
    assert!(
        peak <= with_file + 2 * config_in_force + READ_PEAK_FILES * text.len(),
        "loading a {}-byte file peaked at {peak} bytes, it keeps {with_file}",
        text.len()
    );

    let _ = std::fs::remove_dir_all(&dir);
}
