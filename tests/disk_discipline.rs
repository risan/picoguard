//! The daemon writes to the state folder only when something worth keeping changes. The
//! SBC it runs on has a flash card that wears with every write, so DNS traffic, polling the
//! page, signing in and a list refresh that finds nothing new must leave every file and
//! folder of the state folder as they were, with or without a saved settings file.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::harness::{answering_upstream, name};
use common::http::ListServer;
use common::process::{Running, start_with_web_port};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::RecordType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Whatever a write, an append, a truncate, a rename, a create or a delete leaves behind: the
/// inode, the size and both change times of a file, and of a folder (whose times move when an
/// entry is created, removed or renamed in it).
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn observe(dir: &Path) -> BTreeMap<PathBuf, Seen> {
    fn walk(path: &Path, seen: &mut BTreeMap<PathBuf, Seen>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        seen.insert(
            path.to_path_buf(),
            Seen {
                inode: metadata.ino(),
                size: metadata.size(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            },
        );

        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(&entry.unwrap().path(), seen);
            }
        }
    }

    let mut seen = BTreeMap::new();
    walk(dir, &mut seen);

    seen
}

/// Kernel file times tick every few milliseconds; a pause makes a write after an observation
/// show in the next one.
async fn tick() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn the_observer_sees_a_write_in_place_and_a_file_that_comes_and_goes() {
    let root = common::release::scratch("disk-observer");
    let file = root.join("kept");
    fs::write(&file, b"same size").unwrap();
    let before = observe(&root);
    tick().await;

    fs::write(&file, b"same size").unwrap();

    let after_the_write = observe(&root);
    assert_ne!(after_the_write[&file], before[&file], "a write in place");
    tick().await;

    fs::write(root.join("transient"), b"x").unwrap();
    fs::remove_file(root.join("transient")).unwrap();

    assert_ne!(
        observe(&root)[&root],
        after_the_write[&root],
        "a file created and removed"
    );
}

struct World {
    state: PathBuf,
    web_port: u16,
    dns_port: u16,
    lists: ListServer,
    _upstream: common::harness::FakeUpstream,
    // Held so the child is killed when the test ends.
    _daemon: Stopped,
}

struct Stopped(Running);

impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

async fn world(name: &str, saved_settings: Option<&str>) -> World {
    let state = common::release::scratch(name);
    if let Some(saved) = saved_settings {
        fs::write(state.join("settings.json"), saved).unwrap();
    }

    let upstream = answering_upstream([9, 9, 9, 9], Duration::ZERO).await;
    let lists = ListServer::start().await;
    lists.serve("/with-etag.txt", "||ads.example^\n", Some("\"v1\""));
    lists.serve("/without-etag.txt", "||tracker.example^\n", None);
    let config = |port: u16, web_port: u16| {
        format!(
            "[[lists]]\nurl = {:?}\nformat = \"adblock\"\n\
             [[lists]]\nurl = {:?}\nformat = \"adblock\"\n\
             [server]\nbind = [\"127.0.0.1\"]\nport = {port}\n\
             [upstream]\nservers = [\"udp://{}\"]\n\
             [update]\ncheck = false\n\
             [web]\nuser = \"admin\"\npassword = \"s3cret\"\nbind = [\"127.0.0.1\"]\nport = {web_port}\n\
             [state]\ndir = {state:?}\n",
            lists.url("/with-etag.txt"),
            lists.url("/without-etag.txt"),
            upstream.address,
        )
    };
    let (daemon, web_port) = start_with_web_port(&format!("{name}.toml"), config);
    let dns_port = daemon.port;

    World {
        state,
        web_port,
        dns_port,
        lists,
        _upstream: upstream,
        _daemon: Stopped(daemon),
    }
}

async fn http(port: u16, request: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await.unwrap();

    reply
}

/// `admin` and `s3cret`.
const ADMIN: &str = "YWRtaW46czNjcmV0";

async fn page_call(port: u16, method: &str, path: &str, body: &str) -> String {
    http(
        port,
        &format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
             Authorization: Basic {ADMIN}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

async fn ask(port: u16, text: &str) {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name(text), RecordType::A));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), ("127.0.0.1", port))
        .await
        .unwrap();
    let mut buffer = [0u8; 512];

    tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .unwrap_or_else(|_| panic!("no reply to {text}"))
        .unwrap();
}

/// Seconds since each list was loaded or confirmed current, as the page shows them.
async fn list_ages(world: &World) -> Vec<Option<u64>> {
    let reply = page_call(world.web_port, "GET", "/api/lists", "").await;
    let (_, body) = reply.split_once("\r\n\r\n").expect("a reply with a body");
    let lists: serde_json::Value = serde_json::from_str(body).unwrap_or_else(|error| {
        panic!("{error}: {reply}");
    });

    lists["lists"]
        .as_array()
        .unwrap()
        .iter()
        .map(|list| list["age_seconds"].as_u64())
        .collect()
}

/// Waits until the ages of both lists satisfy `reached`.
async fn until_both_lists(world: &World, what: &str, reached: impl Fn(u64) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let ages = list_ages(world).await;
        if ages.len() == 2 && ages.iter().all(|age| age.is_some_and(&reached)) {
            return;
        }

        assert!(Instant::now() < deadline, "{what}: {ages:?}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Waits until each list has been checked again since the lists aged a second. A refresh
/// ends, snapshot write included, when its list counts as just checked; the lists refresh one
/// after the other, so each is remembered once seen at age 0.
async fn until_each_list_refreshed(world: &World) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut refreshed = [false; 2];
    loop {
        let ages = list_ages(world).await;
        for (done, age) in refreshed.iter_mut().zip(&ages) {
            if *age == Some(0) {
                *done = true;
            }
        }

        if ages.len() == 2 && refreshed.iter().all(|done| *done) {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "the refresh never ended: {ages:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Waits until both lists are in force and saved.
async fn until_the_lists_are_saved(world: &World) {
    for _ in 0..400 {
        let lists = page_call(world.web_port, "GET", "/api/lists", "").await;
        let saved = fs::read_dir(world.state.join("lists")).map_or(0, |entries| entries.count());
        if lists.matches("\"rules\":1").count() == 2 && saved == 2 {
            return;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    panic!("the lists were never loaded and saved");
}

async fn unchanged_workload_leaves_the_state_folder_as_it_was(name: &str, saved: Option<&str>) {
    let world = world(name, saved).await;
    until_the_lists_are_saved(&world).await;
    tick().await;
    let before = observe(&world.state);
    let settings_existed = world.state.join("settings.json").exists();
    assert_eq!(settings_existed, saved.is_some());

    for round in 0..5 {
        for text in ["ads.example.", "tracker.example.", "ok.example."] {
            ask(world.dns_port, text).await;
        }

        let status = page_call(world.web_port, "GET", "/api/status", "").await;
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        let log = page_call(world.web_port, "GET", "/api/querylog", "").await;
        assert!(log.starts_with("HTTP/1.1 200"), "{round}: {log}");
    }

    let login = page_call(
        world.web_port,
        "POST",
        "/api/login",
        "{\"user\": \"admin\", \"password\": \"s3cret\"}",
    )
    .await;
    assert!(login.starts_with("HTTP/1.1 200"), "{login}");

    until_both_lists(&world, "the lists never aged a second", |age| age >= 1).await;
    let requests = world.lists.requests();
    let refresh = page_call(world.web_port, "POST", "/api/lists/refresh", "").await;
    assert!(refresh.starts_with("HTTP/1.1 202"), "{refresh}");

    until_each_list_refreshed(&world).await;

    assert_eq!(world.lists.requests(), requests + 2, "both lists refreshed");
    assert_eq!(world.lists.not_modified(), 1, "one answer was a 304");
    assert_eq!(observe(&world.state), before);
    assert_eq!(world.state.join("settings.json").exists(), settings_existed);
}

#[tokio::test]
async fn dns_polling_signing_in_and_an_unchanged_refresh_write_nothing_without_saved_settings() {
    unchanged_workload_leaves_the_state_folder_as_it_was("disk-no-settings", None).await;
}

#[tokio::test]
async fn dns_polling_signing_in_and_an_unchanged_refresh_write_nothing_beside_saved_settings() {
    unchanged_workload_leaves_the_state_folder_as_it_was(
        "disk-saved-settings",
        Some("{\"version\": 1}"),
    )
    .await;
}
