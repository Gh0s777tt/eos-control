//! `eos-netcfg` — the privileged network helper behind E-OS Control's *Sieć* tab.
//!
//! Three jobs, one binary:
//!
//! ```text
//! echo "$password" | eos-netcfg static <iface> <ip> <prefix> <gw|-> <dns|->
//! echo "$password" | eos-netcfg dhcp   <iface>
//!                    eos-netcfg boot                 # run by init, already root
//! ```
//!
//! **Why it exists.** smolnetd's `netcfg:` scheme rejects every writer whose uid
//! isn't 0 (`EACCES`), and the GUI runs as the desktop user. Instead of elevating
//! a whole Slint app, the GUI spawns this short-lived process with the password on
//! **stdin** and lets it do the [`elevate::to_root`] handshake. Sibling of
//! `eos-power`; same trust model.
//!
//! **Why it writes files too.** Two facts, both confirmed on-device:
//! 1. the desktop user's session namespace has **no `netcfg:` scheme**, so the GUI
//!    can only read `/etc/net/*` (this is the U-113 bug);
//! 2. `dhcpd` configures **only** the scheme and never touches `/etc/net/*` — and
//!    relibc's resolver reads the *file* `/etc/net/dns`, so a DHCP-supplied DNS
//!    server never actually reached user space.
//!
//! So every path here keeps the live scheme and the persistent files in step: an
//! apply is visible in the GUI, survives a reboot, and DNS actually resolves.
//!
//! The scheme layout is recon'd from the smolnetd source (`netcfg` `cfg_node!`
//! tree): `ifaces/<if>/addr/set` takes an `IpCidr`; `route/add` takes
//! `default via <ip>` and needs the address set first (so the gateway is on-link);
//! `route/rm` takes a CIDR (`0.0.0.0/0` is the default route); `resolv/nameserver`
//! takes a single IPv4.

// Shared sudo → procfd → setns elevation (see eos-power).
#[path = "elevate.rs"]
mod elevate;
// Shared parsing + the scheme reader (see src/netcore.rs). The shim uses a subset
// on a host build, where none of the Redox paths compile in.
#[allow(dead_code)]
#[path = "netcore.rs"]
mod netcore;

use netcore::valid_iface;
use std::io::Read;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn usage() -> ! {
    eprintln!("usage: eos-netcfg static <iface> <ip> <prefix> <gw|-> <dns|->   (password on stdin)");
    eprintln!("       eos-netcfg dhcp <iface>                                 (password on stdin)");
    eprintln!("       eos-netcfg boot                                         (root; run by init)");
    std::process::exit(2);
}

/// A validated static configuration. `gateway`/`dns` are optional (`-` on the
/// command line → `None` → left as-is).
struct Cfg {
    iface: String,
    ip: Ipv4Addr,
    prefix: u8,
    gateway: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
}

/// What this invocation should do.
enum Action {
    /// Pin a fixed address (password required).
    Static(Cfg),
    /// Obtain a lease from a DHCP server (password required).
    Dhcp { iface: String },
    /// Boot-time reconciliation, run as root by init — no password, no elevation.
    Boot,
}

fn die(msg: &str) -> ! {
    eprintln!("eos-netcfg: {msg}");
    std::process::exit(2);
}

/// Parse + validate argv. Rejecting bad input here (not only at the scheme) gives
/// a clear message and never leaves a half-written configuration.
fn parse_args() -> Action {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("boot") if a.len() == 1 => Action::Boot,
        Some("dhcp") if a.len() == 2 => {
            let iface = a[1].clone();
            if !valid_iface(&iface) {
                die(&format!("nieprawidłowa nazwa interfejsu: {iface}"));
            }
            Action::Dhcp { iface }
        }
        Some("static") if a.len() == 6 => {
            let iface = a[1].clone();
            if !valid_iface(&iface) {
                die(&format!("nieprawidłowa nazwa interfejsu: {iface}"));
            }
            let ip = Ipv4Addr::from_str(&a[2])
                .unwrap_or_else(|_| die(&format!("nieprawidłowy adres IP: {}", a[2])));
            let prefix: u8 = a[3]
                .parse()
                .ok()
                .filter(|p| *p <= 32)
                .unwrap_or_else(|| die(&format!("prefiks poza zakresem 0–32: {}", a[3])));
            let opt_ip = |s: &str, what: &str| -> Option<Ipv4Addr> {
                if s == "-" {
                    None
                } else {
                    Some(
                        Ipv4Addr::from_str(s)
                            .unwrap_or_else(|_| die(&format!("nieprawidłowy {what}: {s}"))),
                    )
                }
            };
            Action::Static(Cfg {
                iface,
                ip,
                prefix,
                gateway: opt_ip(&a[4], "adres bramy"),
                dns: opt_ip(&a[5], "adres DNS"),
            })
        }
        _ => usage(),
    }
}

fn main() {
    let action = parse_args();
    // `boot` runs as root from init and must never block on stdin; the two
    // user-driven actions read the password from stdin (never argv — that would
    // leak it via `ps`).
    let password = match action {
        Action::Boot => String::new(),
        _ => {
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            buf.lines().next().unwrap_or("").to_string()
        }
    };

    if let Err(e) = run(&action, &password) {
        eprintln!("eos-netcfg: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "redox")]
mod redox_impl {
    use super::{Action, Cfg};
    use crate::netcore::{
        self, netmask_to_prefix, parse_addr_list, parse_default_gateway, prefix_to_netmask, NetMode,
        NET_MODE_PATH,
    };
    use std::time::{Duration, Instant};

    fn scheme(iface: &str, tail: &str) -> String {
        format!("/scheme/netcfg/ifaces/{iface}/{tail}")
    }

    /// Persist the addressing policy. Written *before* the attempt, so a failed
    /// lease still leaves a coherent state (the next boot follows the marker).
    fn write_mode(mode: NetMode) -> Result<(), String> {
        std::fs::write(NET_MODE_PATH, format!("{}\n", mode.as_str()))
            .map_err(|e| format!("{NET_MODE_PATH}: {e}"))
    }

    /// Push an address onto the live stack. smolnetd applies it and inserts the
    /// on-link network route for `<ip>/<prefix>`.
    fn set_addr(iface: &str, ip: &str, prefix: u8) -> Result<(), String> {
        let p = scheme(iface, "addr/set");
        std::fs::write(&p, format!("{ip}/{prefix}\n")).map_err(|e| format!("{p}: {e}"))
    }

    /// Replace the default route. The `rm` first is **required**, not tidiness:
    /// `route/add` does not de-duplicate, so without it an old default route
    /// survives alongside the new one. Removing an absent route is a no-op, so
    /// the `rm` result is deliberately ignored.
    fn set_default_route(gw: &str) -> Result<(), String> {
        let _ = std::fs::write("/scheme/netcfg/route/rm", b"0.0.0.0/0\n");
        std::fs::write("/scheme/netcfg/route/add", format!("default via {gw}\n"))
            .map_err(|e| format!("route/add: {e}"))
    }

    fn set_resolver(dns: &str) -> Result<(), String> {
        std::fs::write("/scheme/netcfg/resolv/nameserver", format!("{dns}\n"))
            .map_err(|e| format!("resolv/nameserver: {e}"))
    }

    /// Write the persistent `/etc/net/*` files the GUI reads and relibc resolves
    /// with. Best-effort per field: a file failure must not undo a live change
    /// that already succeeded.
    fn write_files(ip: &str, subnet: &str, gw: Option<&str>, dns: Option<&str>) {
        let _ = std::fs::write("/etc/net/ip", format!("{ip}\n"));
        let _ = std::fs::write("/etc/net/ip_subnet", format!("{subnet}\n"));
        if let Some(gw) = gw {
            let _ = std::fs::write("/etc/net/ip_router", format!("{gw}\n"));
        }
        if let Some(dns) = dns {
            let _ = std::fs::write("/etc/net/dns", format!("{dns}\n"));
        }
    }

    /// Copy the live scheme state into `/etc/net/*`.
    ///
    /// This is the load-bearing step for DHCP: `dhcpd` configures only the
    /// scheme, while the GUI reads only the files and relibc resolves only from
    /// `/etc/net/dns`. Returns the mirrored address, or `None` if the stack has
    /// no address yet.
    fn mirror_scheme_to_files(iface: &str) -> Option<String> {
        let (ip, prefix) =
            netcore::read_netcfg(&scheme(iface, "addr/list")).and_then(|s| parse_addr_list(&s))?;
        let gw = netcore::read_netcfg("/scheme/netcfg/route/list")
            .as_deref()
            .and_then(parse_default_gateway);
        let dns = netcore::read_netcfg("/scheme/netcfg/resolv/nameserver");
        write_files(&ip, &prefix_to_netmask(prefix), gw.as_deref(), dns.as_deref());
        Some(ip)
    }

    /// Push the persisted `/etc/net/*` configuration onto the live stack — the
    /// boot-time half of "static survives a reboot".
    fn files_to_scheme(iface: &str) -> Result<(), String> {
        let read = |p: &str| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        let ip = read("/etc/net/ip");
        if ip.is_empty() {
            return Err("/etc/net/ip jest puste — brak konfiguracji statycznej".into());
        }
        // A missing/!canonical mask degrades to /24 rather than failing the boot.
        let prefix = netmask_to_prefix(&read("/etc/net/ip_subnet")).unwrap_or(24);
        set_addr(iface, &ip, prefix)?;
        let gw = read("/etc/net/ip_router");
        if !gw.is_empty() {
            set_default_route(&gw)?;
        }
        let dns = read("/etc/net/dns");
        if !dns.is_empty() {
            set_resolver(&dns)?;
        }
        Ok(())
    }

    /// Run the one-shot `dhcpd` client and wait for it. It exits 0 once it has an
    /// ACK; non-zero (or its ~30 s socket timeout) means no server answered.
    fn run_dhcpd() -> Result<(), String> {
        use std::process::{Command, Stdio};
        // Absolute path first: init's environment is minimal and may have no PATH.
        let spawn = |prog: &str| {
            Command::new(prog)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
        };
        let mut child = match spawn("/usr/bin/dhcpd") {
            Ok(c) => c,
            Err(_) => spawn("dhcpd").map_err(|e| format!("nie można uruchomić dhcpd: {e}"))?,
        };
        match child.wait() {
            Ok(st) if st.success() => Ok(()),
            Ok(_) => Err("DHCP: serwer nie odpowiedział (dhcpd)".into()),
            Err(e) => Err(format!("dhcpd: {e}")),
        }
    }

    /// Wait until the stack actually has an address, up to `secs`.
    ///
    /// Needed at boot: `10_dhcpd.service` is `oneshot_async`, so init does **not**
    /// wait for it — we can easily run before the lease lands, and mirroring an
    /// unconfigured stack would persist nothing useful.
    fn wait_for_address(iface: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if netcore::read_netcfg(&scheme(iface, "addr/list"))
                .and_then(|s| parse_addr_list(&s))
                .is_some()
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Apply a static configuration: live scheme first, then the files.
    fn apply_static(cfg: &Cfg) -> Result<(), String> {
        write_mode(NetMode::Static)?;
        set_addr(&cfg.iface, &cfg.ip.to_string(), cfg.prefix)?;
        if let Some(gw) = cfg.gateway {
            set_default_route(&gw.to_string())?;
        }
        if let Some(dns) = cfg.dns {
            set_resolver(&dns.to_string())?;
        }
        write_files(
            &cfg.ip.to_string(),
            &prefix_to_netmask(cfg.prefix),
            cfg.gateway.map(|g| g.to_string()).as_deref(),
            cfg.dns.map(|d| d.to_string()).as_deref(),
        );
        Ok(())
    }

    /// Switch to DHCP: record the policy, drop the old default route, lease, then
    /// mirror what we got into the files.
    fn apply_dhcp(iface: &str) -> Result<(), String> {
        write_mode(NetMode::Dhcp)?;
        // dhcpd adds a default route without removing the old one.
        let _ = std::fs::write("/scheme/netcfg/route/rm", b"0.0.0.0/0\n");
        run_dhcpd()?;
        // Leave /etc/net/* untouched on failure so the GUI keeps showing the last
        // known-good values instead of blanking.
        if mirror_scheme_to_files(iface).is_none() {
            return Err("DHCP: dzierżawa nie przyniosła adresu".into());
        }
        Ok(())
    }

    /// Boot-time reconciliation (already root — no elevation, no password).
    ///
    /// * `static` — push the persisted files onto the live stack, so a static
    ///   address survives the reboot even though `10_dhcpd.service` also ran.
    /// * `dhcp` — wait for the lease, then mirror it into the files. This is what
    ///   makes a DHCP-supplied DNS server reach relibc (which reads
    ///   `/etc/net/dns`) instead of being stranded in the scheme.
    fn boot(iface: &str) -> Result<(), String> {
        match netcore::read_net_mode_at(NET_MODE_PATH) {
            NetMode::Static => files_to_scheme(iface),
            NetMode::Dhcp => {
                if wait_for_address(iface, 20) {
                    let _ = mirror_scheme_to_files(iface);
                }
                // No lease is not a boot failure — the box may simply be offline.
                Ok(())
            }
        }
    }

    pub fn run(action: &Action, password: &str) -> Result<(), String> {
        match action {
            Action::Boot => boot("eth0"),
            Action::Dhcp { iface } => {
                let _sudo = super::elevate::to_root(password)?;
                apply_dhcp(iface)
            }
            Action::Static(cfg) => {
                let _sudo = super::elevate::to_root(password)?;
                apply_static(cfg)
            }
        }
    }
}

#[cfg(target_os = "redox")]
fn run(action: &Action, password: &str) -> Result<(), String> {
    redox_impl::run(action, password)
}

#[cfg(not(target_os = "redox"))]
fn run(_action: &Action, _password: &str) -> Result<(), String> {
    Err("eos-netcfg działa tylko na E-OS".into())
}
