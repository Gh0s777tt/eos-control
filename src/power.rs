//! `eos-power` — a tiny privileged shim for E-OS Control's power actions.
//!
//! Writing the kernel power control `sys:kstop` requires root, and the GUI runs
//! as the desktop user. Rather than elevate the whole GUI process (risky), the
//! GUI spawns this shim, pipes the user's password to its **stdin** (so there is
//! no TTY-password problem), and lets *this* short-lived process do the
//! elevation — exactly the way `sudo` does it internally: open `/scheme/sudo`,
//! write the password (the daemon checks sudo-group membership + the password),
//! then elevate our own process fd and switch namespaces. Once root, we write
//! `sys:kstop` and the machine goes down.
//!
//! Usage: `echo "$password" | eos-power reboot|shutdown`.

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

    // Now root: write the power control. The machine goes down here.
    std::fs::write("/scheme/sys/kstop", action.as_bytes()).map_err(|e| format!("sys:kstop: {e}"))
}

#[cfg(not(target_os = "redox"))]
fn run(_password: &str, _action: &str) -> Result<(), String> {
    Err("eos-power działa tylko na E-OS".into())
}
