//! Shared privilege elevation for E-OS Control's privileged shims.
//!
//! Two shims need to become root to touch a root-only control:
//! `eos-power` (writes `sys:kstop`) and `eos-netcfg` (writes the root-only
//! `netcfg:` scheme). Both elevate the exact way `sudo` does internally: open
//! `/scheme/sudo`, write the password (the daemon checks sudo-group membership +
//! the password), elevate our own process fd, then `setns` into the elevated
//! namespace the daemon prepared. Factored here so there is **one** audited copy
//! of the handshake instead of a per-shim copy (CLAUDE.md §6: shared code over
//! copies).
//!
//! Each shim is a tiny, short-lived process the GUI spawns with the password on
//! its **stdin** — so the GUI itself never runs as root and no password ever
//! reaches a TTY or argv.
//!
//! Usage: `let _sudo = elevate::to_root(password)?;` then do the privileged
//! write while `_sudo` is still in scope (see the note on lifetime below).

/// Elevate the current process to root via `/scheme/sudo`.
///
/// Returns the open `/scheme/sudo` fd on success: **keep it in scope until after
/// the privileged write**. The namespace switch itself is a property of the
/// process (it persists past the handshake), but holding the fd for the duration
/// keeps the elevation window explicit and matches the original `eos-power`
/// lifetime exactly (the fd there lived until the `sys:kstop` write returned).
#[cfg(target_os = "redox")]
pub fn to_root(password: &str) -> Result<libredox::Fd, String> {
    use libredox::flag::O_CLOEXEC;

    // relibc hands us the fd of our own process for the elevation handshake.
    unsafe extern "C" {
        safe fn redox_cur_procfd_v0() -> usize;
    }

    let file = libredox::Fd::open("/scheme/sudo", O_CLOEXEC, 0)
        .map_err(|e| format!("nie można otworzyć /scheme/sudo: {e}"))?;

    // The sudo daemon verifies sudo-group membership + this password.
    file.write(password.as_bytes())
        .map_err(|_| "błędne hasło lub użytkownik spoza grupy sudo".to_string())?;

    // Elevate our own process with the daemon's help (pass our procfd).
    file.call_wo(
        &libredox::call::dup(redox_cur_procfd_v0(), &[])
            .map_err(|e| format!("dup(procfd): {e}"))?
            .to_ne_bytes(),
        syscall::CallFlags::FD,
        &[],
    )
    .map_err(|e| format!("elevacja: {e}"))?;

    // Switch into the elevated namespace the daemon prepared.
    let ns = file
        .openat("ns", O_CLOEXEC, 0)
        .map_err(|e| format!("openat(ns): {e}"))?;
    libredox::call::setns(ns.into_raw()).map_err(|e| format!("setns: {e}"))?;

    // Now root. Hand the sudo fd back so the caller controls when it closes.
    Ok(file)
}

/// Host stub — there is no `/scheme/sudo` off E-OS, so elevation is impossible.
/// The shims are Redox-target tools; the host build exists only so the crate
/// compiles (and the GUI can degrade gracefully) on a developer's box.
#[cfg(not(target_os = "redox"))]
pub fn to_root(_password: &str) -> Result<(), String> {
    Err("elewacja dostępna tylko na E-OS".into())
}
