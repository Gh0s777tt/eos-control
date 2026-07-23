//! `eos-power` — a tiny privileged shim for E-OS Control's power actions.
//!
//! Writing the kernel power control `sys:kstop` requires root, and the GUI runs
//! as the desktop user. Rather than elevate the whole GUI process (risky), the
//! GUI spawns this shim, pipes the user's password to its **stdin** (so there is
//! no TTY-password problem), and lets *this* short-lived process do the
//! elevation via the shared [`elevate::to_root`] handshake. Once root, we write
//! `sys:kstop` and the machine goes down.
//!
//! Usage: `echo "$password" | eos-power reboot|shutdown`.

// The sudo → procfd → setns elevation is shared with `eos-netcfg`; both shims
// pull in the one audited copy rather than duplicating the handshake.
#[path = "elevate.rs"]
mod elevate;

use std::io::Read;

fn usage() -> ! {
    eprintln!("usage: eos-power reboot|shutdown   (password on stdin)");
    std::process::exit(2);
}

fn main() {
    let action = match std::env::args().nth(1).as_deref() {
        Some("reboot") => "reboot",
        Some("shutdown") => "shutdown",
        _ => usage(),
    };
    // Password from stdin (first line); never from argv (that leaks via ps).
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    let password = buf.lines().next().unwrap_or("");

    match run(password, action) {
        Ok(()) => {
            // The machine is going down; nothing more to do.
        }
        Err(e) => {
            eprintln!("eos-power: {e}");
            std::process::exit(1);
        }
    }
}

/// Elevate via `/scheme/sudo`, then write `sys:kstop`. Redox-only.
#[cfg(target_os = "redox")]
fn run(password: &str, action: &str) -> Result<(), String> {
    // Become root; keep the sudo fd alive until the privileged write returns.
    let _sudo = elevate::to_root(password)?;

    // Now root: write the power control. The machine goes down here.
    std::fs::write("/scheme/sys/kstop", action.as_bytes()).map_err(|e| format!("sys:kstop: {e}"))
}

#[cfg(not(target_os = "redox"))]
fn run(_password: &str, _action: &str) -> Result<(), String> {
    Err("eos-power działa tylko na E-OS".into())
}
