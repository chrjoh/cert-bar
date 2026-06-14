//! Hardening of generated private-key files.
//!
//! Generated private keys are sensitive material; by default the OS would write
//! them world-readable (mode `0644`), which exposes them to other local users on
//! shared or CI hosts. After a key is written we restrict it to owner-only
//! (`0600`) on Unix. This is best-effort: if the expected key file is absent
//! (e.g. a CSR-signing step that produces only a certificate) it is a no-op, and
//! on non-Unix platforms it does nothing (Windows ACLs are not addressed here).

use std::path::Path;

/// The on-disk private-key filename convention used by the certificate backend:
/// `<id>_pkey.pem`.
fn key_file_name(id: &str) -> String {
    format!("{id}_pkey.pem")
}

/// Restrict the generated private-key PEM for `id` in `dir` to owner read/write
/// only (`0600`) on Unix. Best-effort — silently does nothing if the file does
/// not exist or the permission change fails.
pub(crate) fn harden_private_key<P: AsRef<Path>>(dir: P, id: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_path = dir.as_ref().join(key_file_name(id));
        if key_path.exists() {
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir.as_ref(), id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_key_file_is_a_noop() {
        // No file present -> must not panic or error.
        let dir = tempfile::tempdir().expect("tempdir");
        harden_private_key(dir.path(), "does-not-exist");
    }

    #[cfg(unix)]
    #[test]
    fn restricts_existing_key_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join(key_file_name("svc"));
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\n").expect("write key");
        // Start world-readable, then harden.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        harden_private_key(dir.path(), "svc");
        let mode = std::fs::metadata(&key).expect("meta").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "private key must be owner-only after hardening"
        );
    }
}
