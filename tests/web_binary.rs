//! The built binary and the status page: served only when `web.enabled` is true.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use common::process::{Running, start};

struct Stopped(Running);

impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(dns_port: u16, web_port: u16, enabled: bool) -> String {
    config_in(dns_port, web_port, enabled, &std::env::temp_dir())
}

fn config_in(dns_port: u16, web_port: u16, enabled: bool, state_dir: &std::path::Path) -> String {
    format!(
        "lists = []\n\
         [server]\nbind = [\"127.0.0.1\"]\nport = {dns_port}\n\
         [upstream]\nservers = [\"udp://127.0.0.1:9\"]\n\
         [update]\ncheck = false\n\
         [web]\nenabled = {enabled}\nbind = [\"127.0.0.1\"]\nport = {web_port}\n\
         [state]\ndir = {state_dir:?}\n"
    )
}

fn fetch(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .ok()?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).ok()?;

    Some(reply)
}

#[test]
fn the_status_page_is_served_when_it_is_enabled() {
    let web_port = free_tcp_port();
    let server = Stopped(start("web-enabled.toml", |port| {
        config(port, web_port, true)
    }));

    let page = fetch(web_port, "/").expect("the page is served");
    let status = fetch(web_port, "/api/status").expect("the status is served");

    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(page.contains("<title>picoguard</title>"));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(status.contains("\"counters\""));
    drop(server);
}

#[test]
fn no_port_is_opened_when_the_status_page_is_disabled() {
    let web_port = free_tcp_port();
    let server = Stopped(start("web-disabled.toml", |port| {
        config(port, web_port, false)
    }));

    assert!(TcpStream::connect(("127.0.0.1", web_port)).is_err());
    drop(server);
}

#[test]
fn a_start_with_the_page_off_removes_update_leftovers() {
    let state = common::release::scratch("web-binary-leftovers");
    let update = state.join("update");
    std::fs::create_dir(&update).unwrap();
    std::fs::write(update.join("picoguard.part"), b"half a download").unwrap();
    let files = common::release::Files::good("9.9.9", b"binary");
    std::fs::write(update.join("request"), &files.request).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(update.join("request"))
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    let web_port = free_tcp_port();

    let server = Stopped(start("web-leftovers.toml", |port| {
        config_in(port, web_port, false, &state)
    }));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::fs::read_dir(&update).unwrap().count() > 0 {
        assert!(std::time::Instant::now() < deadline, "the leftovers stay");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }

    assert!(update.is_dir());
    drop(server);
}
