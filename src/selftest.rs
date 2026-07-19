//! Headless proof of the read cores behind E-OS Control, run by
//! `eos-control --selftest`. Prints `EOS-CONTROL-SELFTEST-OK` on success
//! (asserted from the boot serial / CI). No display. Covers both the system/
//! process core (Overview + Processes tabs) and the security core (Security tab).

use crate::security::{db::Db, db::Status, scan};
use crate::sys;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// Run the self-test. `Ok(())` = every read core behaves.
pub fn run() -> Result<(), String> {
    system_core()?;
    security_core()?;
    Ok(())
}

/// Overview + Processes: a real system identity, ≥1 CPU, consistent counts.
fn system_core() -> Result<(), String> {
    let ov = sys::overview();
    if ov.system.trim().is_empty() {
        return Err("overview system identity is empty".into());
    }
    if ov.cpus == 0 {
        return Err("overview cpu count is 0".into());
    }
    let procs = sys::processes();
    if procs.len() != ov.processes {
        return Err(format!(
            "process count {} disagrees with the list length {}",
            ov.processes,
            procs.len()
        ));
    }
    Ok(())
}

/// Security: baseline a throwaway tree, confirm WAL, confirm a clean re-scan
/// flags the setuid file (the audit), and that a tampered baseline fails its
/// digest. This is the ported eos-guard proof (U-089/U-090).
fn security_core() -> Result<(), String> {
    let db_path = std::env::temp_dir().join("eos-control-selftest.db");
    let _ = fs::remove_file(&db_path);
    let root = std::env::temp_dir().join("eos-control-selftest");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).map_err(|e| format!("mkdir: {e}"))?;
    fs::write(root.join("a.txt"), b"alpha").map_err(|e| format!("write a: {e}"))?;
    let suid = root.join("suid.bin");
    fs::write(&suid, b"root-power").map_err(|e| format!("write suid: {e}"))?;
    fs::set_permissions(&suid, fs::Permissions::from_mode(0o4755))
        .map_err(|e| format!("chmod suid: {e}"))?;
    let roots = vec![root.to_string_lossy().into_owned()];

    let mut db = Db::open(&db_path).map_err(|e| format!("open: {e}"))?;
    if db
        .journal_mode()
        .map_err(|e| format!("journal_mode: {e}"))?
        .to_lowercase()
        != "wal"
    {
        return Err("security db is not in WAL mode".into());
    }
    let (entries, _) = scan::scan_roots(&roots, 10_000);
    if entries.len() != 2 {
        return Err(format!("expected 2 files, scanned {}", entries.len()));
    }
    db.set_baseline(&entries)
        .map_err(|e| format!("set_baseline: {e}"))?;
    if !db.verify_baseline().map_err(|e| format!("verify: {e}"))? {
        return Err("fresh baseline fails its own digest".into());
    }
    let (findings, sum) = db.diff(&entries).map_err(|e| format!("diff: {e}"))?;
    if sum.warn != 1
        || !findings
            .iter()
            .any(|f| f.status == Status::Warn && f.path.ends_with("suid.bin"))
    {
        return Err(format!("audit did not flag the setuid file: {sum:?}"));
    }

    // Tamper the baseline out of band and confirm the digest catches it.
    {
        let conn = rusqlite::Connection::open(&db_path).map_err(|e| format!("reopen raw: {e}"))?;
        conn.execute("UPDATE baseline SET hash = 'deadbeef'", [])
            .map_err(|e| format!("tamper: {e}"))?;
    }
    let db = Db::open(&db_path).map_err(|e| format!("reopen: {e}"))?;
    if db.verify_baseline().map_err(|e| format!("verify2: {e}"))? {
        return Err("tampered baseline still passes its digest".into());
    }

    let _ = fs::remove_dir_all(&root);
    Ok(())
}
