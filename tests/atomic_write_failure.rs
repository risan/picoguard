//! A write that fails half way (a full disk) leaves no `.part` file and keeps the old file.
//!
//! The file size limit is process wide, so this is the only test of its binary.

use std::fs;

use picoguard::atomic::write_file;

const LIMIT_BYTES: u64 = 4096;

#[test]
fn a_write_that_fails_part_way_removes_the_part_and_keeps_the_old_file() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("atomic-write-failure");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("data"), "old").unwrap();

    // Past the limit a write fails with EFBIG, once the kernel's SIGXFSZ is ignored.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: LIMIT_BYTES,
            rlim_max: libc::RLIM_INFINITY,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
    }

    let error = write_file(&dir, "data", &vec![b'x'; 10 * LIMIT_BYTES as usize], None).unwrap_err();

    assert_eq!(error.raw_os_error(), Some(libc::EFBIG), "{error}");
    assert_eq!(fs::read(dir.join("data")).unwrap(), b"old");
    assert!(!dir.join("data.part").exists());
}
