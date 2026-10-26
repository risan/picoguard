//! The update check against a local fake of the GitHub release answer. Nothing leaves the
//! machine: every URL is an IP literal on 127.0.0.1 and the resolver always fails.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::http::ListServer;
use picoguard::lists::Downloader;
use picoguard::update::{Build, Checker, Failure, Latest, Outcome, Updates};
use picoguard::upstream::tls::Tls;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FIXTURE: &str = include_str!("fixtures/github/release-latest.json");
const JSON: Option<&str> = Some("application/json");
const PATH: &str = "/latest";

fn checker(url: &str) -> Checker {
    let downloader = Downloader::new(
        Arc::new(|_| Box::pin(async { Err(io::Error::other("no DNS in this test")) })),
        Arc::new(Tls::with_webpki_roots()),
    );

    Checker::new(downloader, url)
}

fn updates() -> Updates {
    Updates::new(Build::current())
}

fn shown_version(updates: &Updates) -> Option<String> {
    updates.view().latest
}

fn answer(tag: &str) -> String {
    json!({ "tag_name": tag, "draft": false, "prerelease": false, "body": "notes" }).to_string()
}

async fn check(checker: &mut Checker, updates: &Updates) -> Outcome {
    checker.check(updates).await.0
}

async fn with_newer_release() -> (ListServer, Checker, Updates) {
    let server = ListServer::start().await;
    server.serve_typed(PATH, FIXTURE, None, JSON);
    let mut checker = checker(&server.url(PATH));
    let updates = updates();

    assert_eq!(
        check(&mut checker, &updates).await,
        Outcome::Newer("99.0.0".to_string())
    );

    (server, checker, updates)
}

#[tokio::test]
async fn a_newer_release_is_shown_with_its_summary_and_command() {
    let (_server, _checker, updates) = with_newer_release().await;

    let view = updates.view();

    assert_eq!(view.build, Build::current().name());
    assert_eq!(view.latest.as_deref(), Some("99.0.0"));
    assert_eq!(view.how, Some(Build::current().how()));

    let notes = view.notes.expect("the notes are summarized");

    assert!(
        notes.starts_with("## What's new - Update from the status page"),
        "{notes}"
    );
    assert!(!notes.contains("://"), "{notes}");
    assert!(!notes.contains('\n'), "{notes}");
    assert!(notes.chars().count() <= 201, "{notes}");
}

#[tokio::test]
async fn the_second_check_sends_the_etag_and_keeps_the_result_on_304() {
    let server = ListServer::start().await;
    server.serve_typed(PATH, FIXTURE, Some("\"A\""), JSON);
    let mut checker = checker(&server.url(PATH));
    let updates = updates();

    let first = check(&mut checker, &updates).await;
    let second = check(&mut checker, &updates).await;

    assert_eq!(first, Outcome::Newer("99.0.0".to_string()));
    assert_eq!(second, Outcome::Newer("99.0.0".to_string()));
    assert_eq!(server.requests(), 2);
    assert_eq!(server.not_modified(), 1);
    assert_eq!(shown_version(&updates).as_deref(), Some("99.0.0"));
}

#[tokio::test]
async fn a_304_after_an_invalid_answer_repeats_the_invalid_outcome() {
    let server = ListServer::start().await;
    server.serve_typed(PATH, FIXTURE, Some("\"A\""), JSON);
    let mut checker = checker(&server.url(PATH));
    let updates = updates();
    check(&mut checker, &updates).await;

    server.serve_typed(PATH, "{broken", Some("\"B\""), JSON);
    let broken = check(&mut checker, &updates).await;
    let repeated = check(&mut checker, &updates).await;

    assert_eq!(broken, Outcome::Failed(Failure::Invalid));
    assert_eq!(repeated, Outcome::Failed(Failure::Invalid));
    assert_eq!(server.not_modified(), 1);
    assert_eq!(shown_version(&updates).as_deref(), Some("99.0.0"));
}

#[tokio::test]
async fn an_older_or_equal_release_clears_the_notice() {
    for tag in ["v0.0.1", env!("CARGO_PKG_VERSION"), "v0.0.0"] {
        let (server, mut checker, updates) = with_newer_release().await;
        server.serve_typed(PATH, &answer(tag), None, JSON);

        let outcome = check(&mut checker, &updates).await;

        assert_eq!(outcome, Outcome::UpToDate, "{tag}");
        assert_eq!(shown_version(&updates), None, "{tag}");
        assert_eq!(updates.view().how, None, "{tag}");
    }
}

#[tokio::test]
async fn drafts_pre_releases_and_suffixed_tags_keep_the_result() {
    let ignored = [
        json!({ "tag_name": "v100.0.0", "draft": true }),
        json!({ "tag_name": "v100.0.0", "prerelease": true }),
        json!({ "tag_name": "v100.0.0-rc.1" }),
        json!({ "tag_name": "v100.0.0+meta" }),
    ];

    for body in ignored {
        let (server, mut checker, updates) = with_newer_release().await;
        server.serve_typed(PATH, &body.to_string(), None, JSON);

        let outcome = check(&mut checker, &updates).await;

        assert_eq!(outcome, Outcome::Newer("99.0.0".to_string()), "{body}");
        assert_eq!(shown_version(&updates).as_deref(), Some("99.0.0"), "{body}");
    }

    let server = ListServer::start().await;
    server.serve_typed(
        PATH,
        &json!({ "tag_name": "v100.0.0", "draft": true }).to_string(),
        None,
        JSON,
    );
    let mut checker = checker(&server.url(PATH));
    let updates = updates();

    assert_eq!(check(&mut checker, &updates).await, Outcome::UpToDate);
    assert_eq!(shown_version(&updates), None);
}

enum Reply {
    Status(u16),
    Page(String, &'static str),
}

#[tokio::test]
async fn failures_keep_the_last_result() {
    let page = |body: &str, content_type| Reply::Page(body.to_string(), content_type);
    let invalid = Outcome::Failed(Failure::Invalid);
    let cases = [
        (Outcome::NotFound, Reply::Status(404)),
        (Outcome::Failed(Failure::Status(403)), Reply::Status(403)),
        (Outcome::Failed(Failure::Status(500)), Reply::Status(500)),
        (
            invalid.clone(),
            page("<html><body>rate limited</body></html>", "text/html"),
        ),
        (invalid.clone(), page("{broken", "application/json")),
        (
            invalid.clone(),
            page(&"x".repeat(300 * 1024), "application/json"),
        ),
        (
            invalid.clone(),
            page(r#"{"name":"no tag"}"#, "application/json"),
        ),
        (
            invalid.clone(),
            page(r#"{"tag_name":"nightly"}"#, "application/json"),
        ),
    ];

    for (index, (expected, reply)) in cases.into_iter().enumerate() {
        let (server, mut checker, updates) = with_newer_release().await;

        match reply {
            Reply::Status(status) => server.fail(PATH, status),
            Reply::Page(body, content_type) => {
                server.serve_typed(PATH, &body, None, Some(content_type));
            }
        }

        let outcome = check(&mut checker, &updates).await;

        assert_eq!(outcome, expected, "case {index}");
        assert_eq!(
            shown_version(&updates).as_deref(),
            Some("99.0.0"),
            "case {index}"
        );
    }
}

#[tokio::test]
async fn a_closed_port_is_a_network_failure_that_keeps_the_result() {
    let (server, mut checker, updates) = with_newer_release().await;
    server.stop().await;

    let outcome = check(&mut checker, &updates).await;

    assert_eq!(outcome, Outcome::Failed(Failure::Network));
    assert_eq!(shown_version(&updates).as_deref(), Some("99.0.0"));
}

#[tokio::test]
async fn an_empty_body_leaves_the_notes_out() {
    let server = ListServer::start().await;
    let mut checker = checker(&server.url(PATH));
    let updates = updates();

    for body in [
        json!({ "tag_name": "v99.1.0", "body": "" }),
        json!({ "tag_name": "v99.1.0", "body": "  \r\n " }),
        json!({ "tag_name": "v99.1.0", "body": null }),
        json!({ "tag_name": "v99.1.0", "body": "https://example.com/only-a-link" }),
        json!({ "tag_name": "v99.1.0" }),
    ] {
        server.serve_typed(PATH, &body.to_string(), None, JSON);

        let outcome = check(&mut checker, &updates).await;
        let view = updates.view();

        assert_eq!(outcome, Outcome::Newer("99.1.0".to_string()), "{body}");
        assert_eq!(view.latest.as_deref(), Some("99.1.0"), "{body}");
        assert_eq!(view.notes, None, "{body}");
        assert!(view.how.is_some(), "{body}");
    }
}

#[tokio::test]
async fn a_shown_notice_is_replaced_with_the_new_one() {
    let updates = updates();

    updates.show(Some(Latest {
        version: "1.2.3".to_string(),
        notes: "a".to_string(),
    }));
    updates.show(Some(Latest {
        version: "1.2.4".to_string(),
        notes: String::new(),
    }));

    let view = updates.view();

    assert_eq!(view.latest.as_deref(), Some("1.2.4"));
    assert_eq!(view.notes, None);
}

/// Answers each connection in turn with the next of `replies`, then closes it.
async fn raw_server(replies: Vec<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        for reply in replies {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();

            while !head.ends_with(b"\r\n\r\n") {
                let Ok(byte) = stream.read_u8().await else {
                    break;
                };

                head.push(byte);
            }

            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
        }
    });

    address
}

#[tokio::test]
async fn a_body_cut_short_or_too_long_without_a_length_ends_the_check() {
    let cut_short =
        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1000\r\n\r\n0123456789".to_vec();
    let mut endless = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    endless.extend(std::iter::repeat_n(b' ', 300 * 1024));
    let mut good = format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        FIXTURE.len()
    )
    .into_bytes();
    good.extend_from_slice(FIXTURE.as_bytes());
    let address = raw_server(vec![cut_short, endless, good]).await;
    let mut checker = checker(&format!("http://{address}/latest"));
    let updates = updates();
    let limit = Duration::from_secs(5);

    let first = tokio::time::timeout(limit, checker.check(&updates))
        .await
        .unwrap()
        .0;
    let second = tokio::time::timeout(limit, checker.check(&updates))
        .await
        .unwrap()
        .0;

    assert_eq!(first, Outcome::Failed(Failure::Network));
    assert_eq!(second, Outcome::Failed(Failure::Invalid));
    assert_eq!(shown_version(&updates), None);

    let third = tokio::time::timeout(limit, checker.check(&updates))
        .await
        .unwrap()
        .0;

    assert_eq!(third, Outcome::Newer("99.0.0".to_string()));
    assert_eq!(shown_version(&updates).as_deref(), Some("99.0.0"));
}
