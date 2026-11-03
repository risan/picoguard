//! A file that appears whole or not at all.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Writes `<dir>/<name>` as `<name>.part`, synced, then renamed in place and the folder
/// synced. Once it is renamed the file is saved: a failed sync of the folder after that is
/// only logged. A `.part` file left by a crash is replaced. `before_rename` runs between the
/// sync and the rename, for a test.
pub fn write_file(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    before_rename: Option<&(dyn Fn() + Send + Sync)>,
) -> io::Result<()> {
    let part = dir.join(format!("{name}.part"));
    match fs::remove_file(&part) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error);
        }

        _ => {}
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);

    if let Err(error) = written {
        let _ = fs::remove_file(&part);

        return Err(error);
    }

    if let Some(hook) = before_rename {
        hook();
    }

    if let Err(error) = fs::rename(&part, dir.join(name)) {
        let _ = fs::remove_file(&part);

        return Err(error);
    }

    if let Err(error) = File::open(dir).and_then(|dir| dir.sync_all()) {
        log::warn!("saved {name}, but cannot sync {}: {error}", dir.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::test_dir::TestDir;

    use super::*;

    fn names(dir: &TestDir) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();

        names
    }

    #[test]
    fn a_written_file_replaces_the_old_one_and_leaves_no_part() {
        let dir = TestDir::new("atomic-replace");
        fs::write(dir.path().join("data"), "old").unwrap();

        write_file(dir.path(), "data", b"new", None).unwrap();

        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"new");
        assert_eq!(names(&dir), ["data"]);
    }

    #[test]
    fn the_part_file_is_private() {
        let dir = TestDir::new("atomic-mode");
        let mode_in_hook = AtomicBool::new(false);
        let part = dir.path().join("data.part");

        write_file(
            dir.path(),
            "data",
            b"bytes",
            Some(&|| {
                let mode = fs::metadata(&part).unwrap().permissions().mode() & 0o777;
                mode_in_hook.store(mode == 0o600, Ordering::SeqCst);
            }),
        )
        .unwrap();

        assert!(mode_in_hook.load(Ordering::SeqCst));
    }

    #[test]
    fn the_old_file_stays_whole_until_the_rename() {
        let dir = TestDir::new("atomic-before-rename");
        fs::write(dir.path().join("data"), "old").unwrap();
        let seen = std::sync::Mutex::new((Vec::new(), Vec::new()));

        write_file(
            dir.path(),
            "data",
            b"new",
            Some(&|| {
                *seen.lock().unwrap() = (
                    fs::read(dir.path().join("data")).unwrap(),
                    fs::read(dir.path().join("data.part")).unwrap(),
                );
            }),
        )
        .unwrap();

        assert_eq!(*seen.lock().unwrap(), (b"old".to_vec(), b"new".to_vec()));
    }

    #[test]
    fn a_part_left_by_a_crash_is_replaced() {
        let dir = TestDir::new("atomic-stale-part");
        fs::write(dir.path().join("data.part"), "half of an older wri").unwrap();

        write_file(dir.path(), "data", b"whole", None).unwrap();

        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"whole");
        assert_eq!(names(&dir), ["data"]);
    }

    #[test]
    fn a_part_that_is_a_directory_is_an_error_and_changes_nothing() {
        let dir = TestDir::new("atomic-part-is-a-directory");
        fs::write(dir.path().join("data"), "old").unwrap();
        fs::create_dir(dir.path().join("data.part")).unwrap();

        assert!(write_file(dir.path(), "data", b"new", None).is_err());

        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"old");
        assert!(dir.path().join("data.part").is_dir());
    }

    #[test]
    fn a_failed_rename_is_an_error_and_leaves_no_part() {
        let dir = TestDir::new("atomic-rename-fails");
        fs::create_dir(dir.path().join("data")).unwrap();

        assert!(write_file(dir.path(), "data", b"new", None).is_err());

        assert!(dir.path().join("data").is_dir());
        assert_eq!(names(&dir), ["data"]);

        fs::remove_dir(dir.path().join("data")).unwrap();
        write_file(dir.path(), "data", b"next", None).unwrap();

        assert_eq!(fs::read(dir.path().join("data")).unwrap(), b"next");
        assert_eq!(names(&dir), ["data"]);
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let dir = TestDir::new("atomic-missing-dir");

        assert!(write_file(&dir.path().join("missing"), "data", b"x", None).is_err());
        assert!(names(&dir).is_empty());
    }
}
