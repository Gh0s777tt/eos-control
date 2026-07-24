//! `eos-netcfg` — a tiny privileged shim that applies a **static** network
//! configuration to the running stack.
//!
//! smolnetd serves the `netcfg:` scheme, but its `write()` rejects any caller
//! whose uid isn't 0 (`EACCES`) — so a static IP / gateway / DNS change can only
//! come from root, and the GUI runs as the desktop user. Rather than elevate the
//! whole GUI, it spawns this shim, pipes the user's password on **stdin**, and
//! lets this short-lived process do the [`elevate::to_root`] handshake and the
//! writes. Sibling of `eos-power`; same trust model.
//!
//! The scheme paths + formats are recon'd from the smolnetd source (its
//! `netcfg` `cfg_node!` tree): `ifaces/<iface>/addr/set` takes an `IpCidr`
//! (`10.0.2.15/24`); `route/add` takes `default via <ip>` and needs the address
//! set first (so the gateway is on-link); `route/rm` takes a CIDR (`0.0.0.0/0`
//! is the default route); `resolv/nameserver` takes a single IPv4. The scheme
//! writes change the **live** running stack; we then also write the persistent
//! `/etc/net/*` files, both so the change survives a reboot **and** so the
//! desktop-user GUI — whose session has no `netcfg:` scheme, so it reads those
//! files — can see it (see `sys::net`).
//!
//! Usage: `echo "$password" | eos-netcfg <iface> <ip> <prefix> <gw|-> <dns|->`
//! (`-` leaves that field unchanged). Values ride on argv (they aren't secret);
//! only the password is on stdin (never argv — that would leak via `ps`).

// Shared sudo → procfd → setns elevation (see eos-power).
#[path = "elevate.rs"]
mod elevate;

use std::io::Read;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn usage() -> ! {
    eprintln!("usage: eos-netcfg <iface> <ip> <prefix> <gw|-> <dns|->   (password on stdin)");
    std::process::exit(2);
}

/// A validated static configuration to apply. `gateway`/`dns` are optional
/// (`-` on the command line → `None` → left as-is).
struct Cfg {
    iface: String,
    ip: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
}

/// Parse + validate argv into a [`Cfg`]. Rejecting bad input here (not just at
/// the scheme) gives a clear message and never writes a half-configuration.
fn parse_args() -> Cfg {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() != 5 {
        usage();
    }
    let ip = Ipv4Addr::from_str(&a[1]).unwrap_or_else(|_| {
        eprintln!("eos-netcfg: nieprawidłowy adres IP: {}", a[1]);
        std::process::exit(2);
    });
    let prefix: u8 = a[2].parse().ok().filter(|p| *p <= 32).unwrap_or_else(|| {
        eprintln!("eos-netcfg: prefiks poza zakresem 0–32: {}", a[2]);
        std::process::exit(2);
    });
    let opt_ip = |s: &str, what: &str| -> Option<Ipv4Addr> {
        if s == "-" {
            None
        } else {
            Some(Ipv4Addr::from_str(s).unwrap_or_else(|_| {
                eprintln!("eos-netcfg: nieprawidłowy {what}: {s}");
                std::process::exit(2);
            }))
        }
    };
    Cfg {
        iface: a[0].clone(),
        ip,
        prefix,
        gateway: opt_ip(&a[3], "adres bramy"),
        dns: opt_ip(&a[4], "adres DNS"),
    }
}

fn main() {
    let cfg = parse_args();
    // Password from stdin (first line); never from argv (that leaks via ps).
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    let password = buf.lines().next().unwrap_or("");

    match run(password, &cfg) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("eos-netcfg: {e}");
            std::process::exit(1);
        }
    }
}

/// Elevate, then write the static config to the `netcfg:` scheme as root.
/// Order matters: set the address first (so its network route exists and the
/// gateway is on-link), then replace the default route, then the resolver.
#[cfg(target_os = "redox")]
fn run(password: &str, cfg: &Cfg) -> Result<(), String> {
    // Become root; hold the sudo fd until every write is done.
    let _sudo = elevate::to_root(password)?;

    // 1) Interface address (CIDR). smolnetd applies it live + inserts the
    //    on-link network route for `<ip>/<prefix>`.
    let addr_set = format!("/scheme/netcfg/ifaces/{}/addr/set", cfg.iface);
    std::fs::write(&addr_set, format!("{}/{}\n", cfg.ip, cfg.prefix).as_bytes())
        .map_err(|e| format!("{addr_set}: {e}"))?;

    // 2) Default gateway. Remove any existing default (0.0.0.0/0) first so a
    //    change replaces rather than stacks; `route/rm` is idempotent (removing
    //    an absent route is a no-op), so we ignore its result. Then add the new
    //    one — it needs the address from step 1 to be on-link.
    if let Some(gw) = cfg.gateway {
        let _ = std::fs::write("/scheme/netcfg/route/rm", b"0.0.0.0/0\n");
        std::fs::write(
            "/scheme/netcfg/route/add",
            format!("default via {gw}\n").as_bytes(),
        )
        .map_err(|e| format!("route/add: {e}"))?;
    }

    // 3) DNS resolver (single IPv4).
    if let Some(dns) = cfg.dns {
        std::fs::write(
            "/scheme/netcfg/resolv/nameserver",
            format!("{dns}\n").as_bytes(),
        )
        .map_err(|e| format!("resolv/nameserver: {e}"))?;
    }

    // 4) Persist to the /etc/net/* files. This is **not** cosmetic: the desktop
    //    user's session namespace does **not** include the `netcfg:` scheme (only
    //    the `ip`/`tcp`/`udp` sockets — network config is privileged), so the GUI
    //    reads these files, not the scheme (confirmed on-device: `ls /scheme` in
    //    the user session has no `netcfg`). Writing them here — we're root — makes
    //    the applied config **visible** to the GUI's next refresh **and** survive a
    //    reboot. Best-effort: a failure here doesn't undo the live change above.
    let _ = std::fs::write("/etc/net/ip", format!("{}\n", cfg.ip));
    let _ = std::fs::write(
        "/etc/net/ip_subnet",
        format!("{}\n", prefix_to_netmask(cfg.prefix)),
    );
    if let Some(gw) = cfg.gateway {
        let _ = std::fs::write("/etc/net/ip_router", format!("{gw}\n"));
    }
    if let Some(dns) = cfg.dns {
        let _ = std::fs::write("/etc/net/dns", format!("{dns}\n"));
    }

    Ok(())
}

/// Convert an IPv4 prefix length (0–32) to a dotted netmask for `/etc/net/ip_subnet`
/// (`24` → `255.255.255.0`). Mirrors `sys::prefix_to_netmask` (the crate's lib half
/// isn't shared with this standalone shim bin).
#[cfg(target_os = "redox")]
fn prefix_to_netmask(prefix: u8) -> String {
    let p = prefix.min(32) as u32;
    let bits: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let o = bits.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

#[cfg(not(target_os = "redox"))]
fn run(_password: &str, _cfg: &Cfg) -> Result<(), String> {
    Err("eos-netcfg działa tylko na E-OS".into())
}
