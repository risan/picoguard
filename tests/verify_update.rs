//! `verify_update` with a key made for the test: what it copies, what it refuses, and that a
//! path others can change never decides where it writes or what it runs.

mod common;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::time::{Duration, Instant};

use common::release::{
    Files, REQUEST_ID, TARGET, scratch, script, sign_with, stage_dir, sums_line, test_key,
    write_file,
};
use picoguard::release::{Refusal, VerifySetup, verify_update};

const OFFERED: &str = "9.9.9";

fn setup() -> VerifySetup {
    VerifySetup {
        key: test_key(),
        target: Some(TARGET),
        running: env!("CARGO_PKG_VERSION"),
    }
}

fn make_fifo(path: &Path) {
    let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();

    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
}

fn refused(result: Result<picoguard::release::Request, Refusal>) -> Refusal {
    match result {
        Ok(request) => panic!("expected a refusal, got {request:?}"),
        Err(refusal) => refusal,
    }
}

#[test]
fn a_good_update_is_copied_and_verified() {
    let root = scratch("verify-good");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    let into = root.join("out");

    let request = verify_update(&staged, &into, &setup()).unwrap();

    assert_eq!(request.id, REQUEST_ID);
    assert_eq!(request.version, OFFERED);
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&into), 0o700);
    assert_eq!(mode(&into.join("picoguard")), 0o700);

    for name in ["picoguard", "SHA256SUMS", "SHA256SUMS.sig", "request"] {
        assert_eq!(
            fs::read(into.join(name)).unwrap(),
            fs::read(staged.join(name)).unwrap(),
            "{name}"
        );

        if name != "picoguard" {
            assert_eq!(mode(&into.join(name)), 0o600, "{name}");
        }
    }
}

struct Case {
    name: &'static str,
    tweak: fn(&mut Files),
    version: &'static str,
    after: fn(&Path),
    request_is_valid: bool,
    mentions: &'static str,
}

fn nothing(_: &mut Files) {}

fn keep(_: &Path) {}

fn link_to_copy(staged: &Path, name: &str) {
    let copy = staged.parent().unwrap().join(format!("{name}.copy"));
    fs::copy(staged.join(name), &copy).unwrap();
    fs::remove_file(staged.join(name)).unwrap();
    symlink(&copy, staged.join(name)).unwrap();
}

#[test]
fn each_bad_update_is_refused_and_leaves_nothing() {
    let cases = [
        Case {
            name: "bad-signature",
            tweak: |files| files.signature = sign_with(8, &files.sums),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "signature",
        },
        Case {
            name: "short-signature",
            tweak: |files| files.signature.truncate(63),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "signature",
        },
        Case {
            name: "changed-binary",
            tweak: |files| files.binary.push(b'#'),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "does not match",
        },
        Case {
            name: "missing-target-line",
            tweak: |files| files.resign(&sums_line("picoguard-other", &files.binary)),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "no binary",
        },
        Case {
            name: "malformed-request",
            tweak: |files| files.request = b"id=1\n".to_vec(),
            version: OFFERED,
            after: keep,
            request_is_valid: false,
            mentions: "request",
        },
        Case {
            name: "version-not-newer",
            tweak: nothing,
            version: env!("CARGO_PKG_VERSION"),
            after: keep,
            request_is_valid: true,
            mentions: "not newer",
        },
        Case {
            name: "another-version",
            tweak: |files| *files = Files::good(OFFERED, &script("9.9.8")),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "another version",
        },
        Case {
            name: "not-code",
            tweak: |files| *files = Files::good(OFFERED, &[0xa5; 4096]),
            version: OFFERED,
            after: keep,
            request_is_valid: true,
            mentions: "--version",
        },
        Case {
            name: "request-is-a-link",
            tweak: nothing,
            version: OFFERED,
            after: |staged| link_to_copy(staged, "request"),
            request_is_valid: false,
            mentions: "request",
        },
        Case {
            name: "sums-is-a-link",
            tweak: nothing,
            version: OFFERED,
            after: |staged| link_to_copy(staged, "SHA256SUMS"),
            request_is_valid: true,
            mentions: "SHA256SUMS",
        },
        Case {
            name: "signature-is-a-link",
            tweak: nothing,
            version: OFFERED,
            after: |staged| link_to_copy(staged, "SHA256SUMS.sig"),
            request_is_valid: true,
            mentions: "SHA256SUMS.sig",
        },
        Case {
            name: "binary-is-a-link",
            tweak: nothing,
            version: OFFERED,
            after: |staged| link_to_copy(staged, "picoguard"),
            request_is_valid: true,
            mentions: "picoguard",
        },
        Case {
            name: "binary-is-a-fifo",
            tweak: nothing,
            version: OFFERED,
            after: |staged| {
                fs::remove_file(staged.join("picoguard")).unwrap();
                make_fifo(&staged.join("picoguard"));
            },
            request_is_valid: true,
            mentions: "regular file",
        },
        Case {
            name: "missing-file",
            tweak: nothing,
            version: OFFERED,
            after: |staged| fs::remove_file(staged.join("SHA256SUMS")).unwrap(),
            request_is_valid: true,
            mentions: "SHA256SUMS",
        },
        Case {
            name: "parent-writable-by-others",
            tweak: nothing,
            version: OFFERED,
            after: |staged| {
                let parent = staged.parent().unwrap().join("open");
                fs::create_dir(&parent).unwrap();
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
            },
            request_is_valid: true,
            mentions: "into-dir",
        },
    ];

    for case in cases {
        let root = scratch(&format!("verify-bad-{}", case.name));
        let staged = stage_dir(&root, case.version, &script(OFFERED), case.tweak);
        (case.after)(&staged);
        let into = if case.name == "parent-writable-by-others" {
            root.join("open/out")
        } else {
            root.join("out")
        };

        let started = Instant::now();
        let refusal = refused(verify_update(&staged, &into, &setup()));

        assert!(
            refusal.reason.contains(case.mentions),
            "{}: {:?}",
            case.name,
            refusal.reason
        );
        assert!(
            refusal.reason.len() <= 200 && !refusal.reason.contains('\n'),
            "{}: {:?}",
            case.name,
            refusal.reason
        );
        assert_eq!(
            refusal.request.is_some(),
            case.request_is_valid,
            "{}",
            case.name
        );
        assert!(!into.exists(), "{}: the destination was left", case.name);
        assert!(started.elapsed() < Duration::from_secs(5), "{}", case.name);
    }
}

#[test]
fn an_existing_into_dir_is_left_alone() {
    let root = scratch("verify-existing");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    let into = root.join("out");
    fs::create_dir(&into).unwrap();
    write_file(&into.join("sentinel"), b"keep", 0o600);

    let refusal = refused(verify_update(&staged, &into, &setup()));

    assert!(refusal.request.is_some());
    assert_eq!(fs::read(into.join("sentinel")).unwrap(), b"keep");
    assert_eq!(fs::read_dir(&into).unwrap().count(), 1);

    let target = root.join("elsewhere");
    fs::create_dir(&target).unwrap();
    write_file(&target.join("sentinel"), b"keep", 0o600);
    let link = root.join("link");
    symlink(&target, &link).unwrap();

    let refusal = refused(verify_update(&staged, &link, &setup()));

    assert!(refusal.request.is_some());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);
    assert_eq!(fs::read_link(&link).unwrap(), target);
}

#[test]
fn a_path_others_can_change_is_refused() {
    let root = scratch("verify-others");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});

    // The scratch root and everything above it must be ours and closed, or the second case
    // proves nothing.
    let mut ancestor = Some(root.as_path());
    while let Some(path) = ancestor {
        let mode = fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o022,
            0,
            "{} is writable by others: this test needs a closed path above the scratch root",
            path.display()
        );
        ancestor = path.parent();
    }

    let open = root.join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();

    let refusal = refused(verify_update(&staged, &open.join("out"), &setup()));

    assert!(refusal.request.is_some());
    assert!(!open.join("out").exists());

    let closed = open.join("closed");
    fs::create_dir(&closed).unwrap();
    fs::set_permissions(&closed, fs::Permissions::from_mode(0o700)).unwrap();

    let refusal = refused(verify_update(&staged, &closed.join("out"), &setup()));

    assert!(refusal.request.is_some());
    assert!(!closed.join("out").exists());
}

#[test]
fn a_relative_into_dir_works() {
    let root = scratch("verify-relative");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    let relative = Path::new("target/tmp/verify-relative/out");
    assert!(
        std::env::current_dir()
            .unwrap()
            .ends_with(Path::new(env!("CARGO_MANIFEST_DIR")).file_name().unwrap()),
        "cargo runs integration tests in the package root"
    );

    let request = verify_update(&staged, relative, &setup()).unwrap();

    assert_eq!(request.version, OFFERED);
    assert!(root.join("out/picoguard").is_file());
}

#[test]
fn a_parent_alias_cannot_redirect_the_run() {
    let root = scratch("verify-alias");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    let marker = root.join("marker");
    let real = root.join("real");
    let evil = root.join("evil");
    fs::create_dir(&real).unwrap();
    fs::create_dir_all(evil.join("out")).unwrap();
    write_file(
        &evil.join("out/picoguard"),
        format!(
            "#!/bin/sh\necho ran > {}\necho \"picoguard {OFFERED}\"\n",
            marker.display()
        )
        .as_bytes(),
        0o755,
    );
    let alias = root.join("alias");

    for round in 0..20u64 {
        let _ = fs::remove_dir_all(real.join("out"));
        let _ = fs::remove_file(&alias);
        symlink(&real, &alias).unwrap();
        let swapper = {
            let (alias, evil, root) = (alias.clone(), evil.clone(), root.clone());

            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_micros(round * 150));
                let swap = root.join("alias.swap");
                let _ = fs::remove_file(&swap);
                symlink(&evil, &swap).unwrap();
                fs::rename(&swap, &alias).unwrap();
            })
        };

        let result = verify_update(&staged, &alias.join("out"), &setup());
        swapper.join().unwrap();

        match result {
            Ok(_) => assert!(real.join("out/picoguard").is_file(), "round {round}"),
            Err(refusal) => assert!(
                refusal.reason.contains("exists"),
                "round {round}: {:?}",
                refusal.reason
            ),
        }

        assert!(!marker.exists(), "round {round}: ran through the alias");
    }
}

#[test]
fn a_fifo_that_replaces_a_file_never_blocks() {
    let root = scratch("verify-fifo");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    fs::remove_file(staged.join("picoguard")).unwrap();
    make_fifo(&staged.join("picoguard"));

    let started = Instant::now();
    let refusal = refused(verify_update(&staged, &root.join("out"), &setup()));

    assert!(refusal.request.is_some());
    assert!(started.elapsed() < Duration::from_secs(1));

    for round in 0..20u64 {
        let root = scratch("verify-fifo-swap");
        let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
        let into = root.join("out");
        let swapper = {
            let staged = staged.clone();

            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_micros(round * 100));
                let fifo = staged.join("picoguard.fifo");
                make_fifo(&fifo);
                fs::rename(&fifo, staged.join("picoguard")).unwrap();
            })
        };

        let started = Instant::now();
        let result = verify_update(&staged, &into, &setup());
        swapper.join().unwrap();

        assert!(started.elapsed() < Duration::from_secs(1), "round {round}");
        if result.is_err() {
            assert!(!into.exists(), "round {round}");
        }
    }
}

#[test]
fn a_build_without_a_target_cannot_verify() {
    let root = scratch("verify-no-target");
    let staged = stage_dir(&root, OFFERED, &script(OFFERED), |_| {});
    let into = root.join("out");
    let setup = VerifySetup {
        target: None,
        ..setup()
    };

    let refusal = refused(verify_update(&staged, &into, &setup));

    assert_eq!(refusal.reason, "this build cannot verify updates");
    assert!(!into.exists());
}
