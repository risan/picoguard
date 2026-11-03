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

    fs::rename(&part, dir.join(name))?;

    if let Err(error) = File::open(dir).and_then(|dir| dir.sync_all()) {
        log::warn!("saved {name}, but cannot sync {}: {error}", dir.display());
    }

    Ok(())
}
