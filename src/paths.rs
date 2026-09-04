//! Where the Security tab keeps its baseline database. A product decision, kept OUT of
//! the shared `eos-fsintegrity` crate on purpose: the path is the only place where "one
//! engine" could quietly become "one file for every product".
//!
//! The value is byte-for-byte what the ported `db::default_path()` returned before
//! `PR-004` -- including the `eos-guard` directory, because the ported copy carried it.
//! Whether Control and Guard should keep sharing this file is an open owner decision, and
//! this module changes nothing about it.

use std::path::{Path, PathBuf};

/// `$HOME/.local/share/eos-guard/baseline.db`, or `/tmp/eos-guard.db` without a `HOME`.
pub fn baseline_db() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".local")
            .join("share")
            .join("eos-guard")
            .join("baseline.db"),
        None => PathBuf::from("/tmp/eos-guard.db"),
    }
}

#[cfg(test)]
mod tests {
    use super::baseline_db;

    /// The path this product opens is the one it opened before the engine moved out.
    #[test]
    fn the_baseline_lives_where_it_always_did() {
        let s = baseline_db().to_string_lossy().into_owned();
        assert!(
            s.ends_with("/.local/share/eos-guard/baseline.db") || s == "/tmp/eos-guard.db",
            "{s}"
        );
    }
}
