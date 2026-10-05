//! Test-only: write a shell script that stands in for the routing host and
//! make sure it can be exec'd.
//!
//! Exec'ing a file another process still holds open for writing fails with
//! ETXTBSY ("Text file busy"). Closing our handle is not enough under
//! `cargo test`'s parallel threads: a sibling test that forks between our
//! `open` and `close` hands the write fd to its child until that child execs,
//! so the first spawn of a freshly written script can fail at random. That
//! was the `host_process::tests::failures_name_their_reason` flake.
//!
//! [`write_executable_script`] closes and syncs the file, then runs it once in
//! a no-op mode (the script exits before its body when
//! `F2F_TEST_SCRIPT_WARMUP` is set), retrying on ETXTBSY. Once one spawn has
//! succeeded no process holds a write fd any more (ours is closed, and later
//! forks cannot inherit a closed fd), so every later spawn by the test is safe.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

const WARMUP_VAR: &str = "F2F_TEST_SCRIPT_WARMUP";

/// Write `#!/bin/sh` + `body` to `path`, mark it 0755, and wait until it can
/// be exec'd. `body` runs only for real invocations, never for the warm-up.
pub(crate) fn write_executable_script(path: &Path, body: &str) {
    {
        let mut file = std::fs::File::create(path).expect("create script");
        write!(
            file,
            "#!/bin/sh\n[ -n \"${WARMUP_VAR}\" ] && exit 0\n{body}"
        )
        .expect("write script");
        file.sync_all().expect("sync script");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod script");
    for _ in 0..200 {
        match Command::new(path)
            .env(WARMUP_VAR, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(_) => return,
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("warm-up spawn of {}: {err}", path.display()),
        }
    }
    panic!("{} stayed busy (ETXTBSY) for 1s", path.display());
}
