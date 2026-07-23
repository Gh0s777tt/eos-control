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
    kill_core()?;
    net_core()?;
    storage_core()?;
    audio_core()?;
    power_core()?;
    Ok(())
}

/// Audio: the volume read core + its parse/clamp helpers must behave, and must
/// **not** move the real level at boot. `sys::set_volume` writes the daemon, so
/// like the power actions it is only *referenced* here (proven live by the
/// render test, where the Sound-tab slider drives it); the read path and the
/// pure helpers are side-effect free, so we exercise those.
fn audio_core() -> Result<(), String> {
    // Pure helpers underpin every slider value we hand the daemon.
    if sys::clamp_volume(150) != 100 || sys::clamp_volume(-5) != 0 || sys::clamp_volume(42) != 42 {
        return Err("clamp_volume is out of the 0–100 range".into());
    }
    if sys::parse_volume(" 73 \n") != Some(73) {
        return Err("parse_volume did not round-trip the daemon's format".into());
    }
    if sys::parse_volume("nope").is_some() {
        return Err("parse_volume accepted non-numeric input".into());
    }
    // Read path must not panic; a reported level (when available) stays in range.
    let a = sys::audio();
    if a.available && (a.volume < 0 || a.volume > 100) {
        return Err(format!("audio volume {} out of range", a.volume));
    }
    // Reference the setter without calling it (it would move the live level).
    let _set: fn(i32) -> Result<(), String> = sys::set_volume;
    Ok(())
}

/// Power: the reboot/shutdown functions must **not** run here — the self-test
/// executes during boot (an init.d probe), and calling them would halt the
/// machine mid-boot. Only reference them (so the CLI build doesn't flag them
/// dead); the actions are proven by the render test, where clicking Reboot
/// actually reboots the VM.
fn power_core() -> Result<(), String> {
    let _reboot: fn(&str) -> Result<(), String> = sys::reboot;
    let _shutdown: fn(&str) -> Result<(), String> = sys::shutdown;
    Ok(())
}

/// Storage: `statvfs` must not panic and must be self-consistent. Where a real
/// filesystem answers (total > 0) free must not exceed total; a zero result
/// (unsupported) is tolerated rather than failing boot.
fn storage_core() -> Result<(), String> {
    let st = sys::storage();
    if st.total_bytes != 0 && st.free_bytes > st.total_bytes {
        return Err("storage free exceeds total".into());
    }
    Ok(())
}

/// Network: the read core (live netcfg + `/etc/net` fallback) must not panic,
/// and every pure helper behind the Sieć tab's static editor must behave — those
/// helpers gate what we hand the privileged `eos-netcfg` shim, so they carry the
/// correctness weight the render test can't reach headlessly. `apply_static`
/// itself is only *referenced* (calling it with valid input would spawn the shim
/// and reconfigure the running network mid-boot); we exercise its **validation**
/// path with known-bad input, which rejects before any spawn.
fn net_core() -> Result<(), String> {
    let net = sys::net();
    // Touch every field so the read core is exercised end to end (and the
    // CLI-only build doesn't flag the GUI-read fields as dead).
    let _summary = format!(
        "iface={} ip={} gw={} dns={} mask={} mac={} stack={}",
        net.iface, net.ip, net.gateway, net.dns, net.subnet, net.mac, net.stack_up
    );
    if std::path::Path::new("/etc/net/ip").exists() && net.ip.is_empty() {
        return Err("/etc/net/ip is present but sys::net() read no address".into());
    }

    // addr/list parse: a real CIDR splits; placeholders + an out-of-range prefix
    // are rejected so they can't masquerade as an address.
    if sys::parse_addr_list("10.0.2.15/24") != Some(("10.0.2.15".to_string(), 24)) {
        return Err("parse_addr_list did not split a valid CIDR".into());
    }
    if sys::parse_addr_list("Not configured").is_some()
        || sys::parse_addr_list("10.0.2.15/40").is_some()
    {
        return Err("parse_addr_list accepted a placeholder / out-of-range prefix".into());
    }

    // prefix ↔ netmask must round-trip and hit the edges.
    if sys::prefix_to_netmask(24) != "255.255.255.0"
        || sys::prefix_to_netmask(0) != "0.0.0.0"
        || sys::prefix_to_netmask(32) != "255.255.255.255"
        || sys::prefix_to_netmask(25) != "255.255.255.128"
    {
        return Err("prefix_to_netmask produced a wrong mask".into());
    }
    if sys::netmask_to_prefix("255.255.255.0") != Some(24)
        || sys::netmask_to_prefix("255.255.255.255") != Some(32)
        || sys::netmask_to_prefix("0.0.0.0") != Some(0)
        || sys::netmask_to_prefix("255.0.255.0").is_some()
    // non-contiguous → rejected
    {
        return Err("netmask_to_prefix mishandled a mask".into());
    }

    // IP + prefix validators.
    if !sys::valid_ipv4("10.0.2.2") || sys::valid_ipv4("999.0.0.1") || sys::valid_ipv4("") {
        return Err("valid_ipv4 misjudged an address".into());
    }
    if !sys::valid_prefix(24) || sys::valid_prefix(33) || sys::valid_prefix(-1) {
        return Err("valid_prefix misjudged a prefix".into());
    }

    // Default gateway extraction from a route/list dump.
    let routes =
        "default  via 10.0.2.2 dev eth0 src 10.0.2.15\n10.0.2.0/24  dev eth0 src 10.0.2.15\n";
    if sys::parse_default_gateway(routes).as_deref() != Some("10.0.2.2") {
        return Err("parse_default_gateway missed the default route's via".into());
    }
    if sys::parse_default_gateway("10.0.2.0/24 dev eth0 src 10.0.2.15").is_some() {
        return Err("parse_default_gateway invented a gateway with no default route".into());
    }

    // Validation must reject bad input *before* spawning the shim — three
    // representative failures (bad ip / prefix / gateway).
    if sys::apply_static("eth0", "not-an-ip", 24, "", "", "x").is_ok() {
        return Err("apply_static accepted a bad IP".into());
    }
    if sys::apply_static("eth0", "10.0.0.5", 40, "", "", "x").is_ok() {
        return Err("apply_static accepted an out-of-range prefix".into());
    }
    if sys::apply_static("eth0", "10.0.0.5", 24, "garbage", "", "x").is_ok() {
        return Err("apply_static accepted a bad gateway".into());
    }
    // Reference the setter without a valid-input call (that would reconfigure the
    // live network); the render test proves the apply end to end.
    let _apply: fn(&str, &str, i32, &str, &str, &str) -> Result<(), String> = sys::apply_static;
    Ok(())
}

/// ForceKill: spawn a throwaway child, force-kill it by pid, and confirm it dies.
/// Proves the Processes-tab "Wymuś zamknięcie" path end to end. Tolerant of an
/// environment without a spawnable helper (skips rather than failing boot).
fn kill_core() -> Result<(), String> {
    use std::process::Command;
    use std::time::{Duration, Instant};
    // A long-lived child we can safely kill. If we can't spawn one (no `sleep`
    // on PATH) we can't prove the path here — skip without failing.
    let mut child = match Command::new("sleep").arg("30").spawn() {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let pid = child.id() as i64;
    sys::kill(pid).map_err(|e| format!("ForceKill returned an error: {e}"))?;
    // It must exit promptly; poll up to ~3 s so a failed kill can't hang boot.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()), // reaped → it died
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill(); // clean the leak up on failure
                    let _ = child.wait();
                    return Err("process still alive 3 s after ForceKill".into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("try_wait after ForceKill: {e}")),
        }
    }
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
    // The byte parse/format pair underpins per-group memory sums (Processes tab).
    if sys::parse_bytes("1 MB") != 1024 * 1024 {
        return Err(format!(
            "parse_bytes(\"1 MB\") = {}",
            sys::parse_bytes("1 MB")
        ));
    }
    if sys::fmt_bytes(1024 * 1024) != "1.0 MB" {
        return Err(format!(
            "fmt_bytes(1 MiB) = {}",
            sys::fmt_bytes(1024 * 1024)
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
