//! System + process state — the non-GUI core behind the Overview and Processes
//! tabs of E-OS Control.
//!
//! On Redox/E-OS this reads the kernel `sys:` scheme (`sys:uname`, `sys:cpu`,
//! `sys:stat`, `sys:context`, `sys:iostat`); on a host it reads `/proc` so the
//! CLI/selftest half stays honest. Everything here is a plain read + parse — no
//! GUI — which is what makes it provable headlessly.
//!
//! The standout is the **capability inspector**: `sys:iostat` lists, per process,
//! every open file descriptor with its scheme path, so we can show what each
//! process can actually touch — its resource/capability profile. On a
//! capability-secure microkernel that is impossible to hide, unlike on Windows.

use crate::labels;

/// A one-glance summary of the machine, shown on the Overview tab.
#[derive(Clone, Debug, Default)]
pub struct Overview {
    /// System identity, e.g. `E-OS (Redox 0.9.0) · aarch64`.
    pub system: String,
    /// Logical CPU count.
    pub cpus: u32,
    /// Number of processes/contexts.
    pub processes: usize,
    /// Total private memory across all processes, in bytes (summed from the
    /// process list) — the "how much RAM is in use" figure.
    pub mem_bytes: u64,
    /// Context switches since boot (from `sys:stat`), if available.
    pub context_switches: u64,
    /// Total hardware IRQs served (from `sys:stat`), if available.
    pub irqs: u64,
}

/// One process, enriched with a human label and its capability (open-scheme) set.
#[derive(Clone, Debug, Default)]
pub struct Proc {
    /// Process id.
    pub pid: String,
    /// Process name (argv[0]).
    pub name: String,
    /// A short human explanation of what this process is (E-OS daemons etc.).
    pub label: String,
    /// Owning user id (EUID column).
    pub owner: String,
    /// Scheduler status (STAT column).
    pub status: String,
    /// Accumulated CPU time (TIME column).
    pub cpu_time: String,
    /// Private memory (PRIVATE column), a pre-formatted size like `1 MB`.
    pub memory: String,
    /// Private memory in bytes (parsed from `memory`), so groups can sum it.
    pub mem_bytes: u64,
    /// The schemes this process holds open — its capability profile.
    pub resources: Vec<String>,
}

/// Parse a kernel-formatted size (`"1 MB"`, `"512 KB"`, `"1024 B"`) into bytes.
pub fn parse_bytes(s: &str) -> u64 {
    let s = s.trim();
    let (num, unit) = match s.split_once(' ') {
        Some((n, u)) => (n, u.trim()),
        None => (s, "B"),
    };
    let n: f64 = num.trim().parse().unwrap_or(0.0);
    let mult: f64 = match unit {
        "KB" | "KiB" => 1024.0,
        "MB" | "MiB" => 1024.0 * 1024.0,
        "GB" | "GiB" => 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (n * mult) as u64
}

/// Format a byte count back into a compact `"1.2 MB"`-style string.
pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Force-kill a process by pid (SIGKILL). On E-OS this is the kernel's
/// unblockable ForceKill; on a host it's POSIX `kill(2)`. Use when a process
/// is stuck or misbehaving.
#[cfg(target_os = "redox")]
pub fn kill(pid: i64) -> Result<(), String> {
    // `libredox::call::kill` is how E-OS daemons (audiod, ptyd) signal; relibc
    // routes SIGKILL to the kernel's unblockable ForceKill.
    libredox::call::kill(pid as usize, libredox::flag::SIGKILL as u32)
        .map_err(|e| format!("kill {pid}: {e}"))
}

/// Force-kill a process by pid (SIGKILL). See the Redox variant.
#[cfg(not(target_os = "redox"))]
pub fn kill(pid: i64) -> Result<(), String> {
    // SAFETY: `kill` is a simple syscall with no memory effects.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("kill {pid}: {}", std::io::Error::last_os_error()))
    }
}

/// Take an Overview snapshot. Never panics — unreadable sources degrade to 0/empty.
pub fn overview() -> Overview {
    #[cfg(target_os = "redox")]
    {
        redox::overview()
    }
    #[cfg(not(target_os = "redox"))]
    {
        host::overview()
    }
}

/// Take a process snapshot (with labels + capability sets). Never panics.
pub fn processes() -> Vec<Proc> {
    #[cfg(target_os = "redox")]
    {
        redox::processes()
    }
    #[cfg(not(target_os = "redox"))]
    {
        host::processes()
    }
}

/// Network configuration + stack status, shown on the Network tab.
///
/// Reads the **live** `netcfg:` scheme smolnetd serves — the authoritative
/// running config — and falls back to the persistent `/etc/net/*` files the base
/// image ships (which dhcpd keeps current) when the scheme is unreadable. The
/// scheme layout was recon'd from the smolnetd source (`netcfg` `cfg_node!`
/// tree): `ifaces` lists interfaces; `ifaces/<iface>/addr/list` gives `ip/prefix`
/// (or the placeholders "Not configured" / "Device not found"); `route/list`
/// carries the routing table; `resolv/nameserver` the DNS resolver; and
/// `ifaces/<iface>/mac` the hardware address. All plain reads — on a host both
/// the scheme and the files are absent so every field degrades to empty /
/// `stack_up = false`.
#[derive(Clone, Debug, Default)]
pub struct Net {
    /// Interface name, e.g. `eth0` (smolnetd currently serves a single `eth0`).
    pub iface: String,
    /// Interface IPv4 address, e.g. `10.0.2.15`.
    pub ip: String,
    /// Default gateway (the default route's `via`, else `/etc/net/ip_router`).
    pub gateway: String,
    /// DNS resolver.
    pub dns: String,
    /// Subnet mask, derived from the live prefix or read from `/etc/net/ip_subnet`.
    pub subnet: String,
    /// Interface hardware (MAC) address, informational; empty if unavailable.
    pub mac: String,
    /// True when the `ip` scheme is present — i.e. netstack/smolnetd is running.
    pub stack_up: bool,
}

/// Read a single-line `netcfg:` value, mapping smolnetd's placeholder strings
/// ("Not configured", "Device not found") and unreadable/empty results to
/// `None`, so a placeholder can never masquerade as a real value.
fn read_netcfg(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    if s.is_empty() || s == "Not configured" || s == "Device not found" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse the netcfg `ifaces/<iface>/addr/list` payload (`"10.0.2.15/24"`) into
/// `(ip, prefix)`. `None` for a non-CIDR value (placeholders included), so the
/// caller can fall back rather than show garbage.
pub fn parse_addr_list(s: &str) -> Option<(String, u8)> {
    let (ip, prefix) = s.trim().split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((ip.to_string(), prefix))
}

/// Convert an IPv4 prefix length (0–32) to a dotted netmask (`24` → `255.255.255.0`).
pub fn prefix_to_netmask(prefix: u8) -> String {
    let p = prefix.min(32) as u32;
    // p == 0 → 0.0.0.0; a plain `MAX << 32` would overflow-panic, so special-case
    // it. For 1..=32 the shift amount is 0..=31, always in range.
    let bits: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let o = bits.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// True if `s` parses as an IPv4 address.
pub fn valid_ipv4(s: &str) -> bool {
    s.trim().parse::<std::net::Ipv4Addr>().is_ok()
}

/// True if `p` is a valid IPv4 prefix length (0–32).
pub fn valid_prefix(p: i32) -> bool {
    (0..=32).contains(&p)
}

/// Convert a dotted netmask to a prefix length (`255.255.255.0` → `24`). `None`
/// if it isn't a canonical mask (contiguous ones followed by zeros) — used only
/// to pre-fill the edit form's prefix box, so a weird mask just leaves it blank.
pub fn netmask_to_prefix(mask: &str) -> Option<u8> {
    let addr: std::net::Ipv4Addr = mask.trim().parse().ok()?;
    let bits = u32::from(addr);
    let ones = bits.leading_ones();
    // Reject non-contiguous masks: the ones-count must reconstruct the value.
    let canonical = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    if bits == canonical {
        Some(ones as u8)
    } else {
        None
    }
}

/// Pull the default-route gateway out of the netcfg `route/list` dump. Lines
/// read `default  via 10.0.2.2 dev eth0 src 10.0.2.15` (non-default routes have
/// no `via`); we take the `via` token from the `default` line.
pub fn parse_default_gateway(route_list: &str) -> Option<String> {
    for line in route_list.lines() {
        if !line.trim_start().starts_with("default") {
            continue;
        }
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "via" {
                return it.next().map(str::to_string);
            }
        }
    }
    None
}

/// Read the current network configuration + stack status. Prefers the live
/// `netcfg:` scheme, falls back to `/etc/net/*`. Never panics; any unreadable
/// source degrades to empty / `false`.
pub fn net() -> Net {
    let file = |p: &str| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .trim()
            .to_string()
    };

    // Interface: the first name smolnetd lists (it serves a single `eth0`);
    // default to `eth0` when the scheme isn't up.
    let iface = read_netcfg("/scheme/netcfg/ifaces")
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "eth0".to_string());

    // Live address (authoritative) → ip + derived netmask; else the /etc/net files.
    let (ip, subnet) = match read_netcfg(&format!("/scheme/netcfg/ifaces/{iface}/addr/list"))
        .as_deref()
        .and_then(parse_addr_list)
    {
        Some((ip, prefix)) => (ip, prefix_to_netmask(prefix)),
        None => (file("/etc/net/ip"), file("/etc/net/ip_subnet")),
    };

    // Gateway: the default route's `via`, else the persistent router file.
    let gateway = read_netcfg("/scheme/netcfg/route/list")
        .as_deref()
        .and_then(parse_default_gateway)
        .unwrap_or_else(|| file("/etc/net/ip_router"));

    // DNS resolver: the live resolver, else the persistent file.
    let dns =
        read_netcfg("/scheme/netcfg/resolv/nameserver").unwrap_or_else(|| file("/etc/net/dns"));

    // MAC (informational).
    let mac = read_netcfg(&format!("/scheme/netcfg/ifaces/{iface}/mac")).unwrap_or_default();

    // The `ip` scheme only appears once netstack has registered it; listing
    // `/scheme` is the reliable probe (statting `/scheme/ip` directly is a
    // socket op, not a file op). On a host `/scheme` is absent → false.
    let stack_up = std::fs::read_dir("/scheme")
        .map(|rd| rd.filter_map(|e| e.ok()).any(|e| e.file_name() == "ip"))
        .unwrap_or(false);

    Net {
        iface,
        ip,
        gateway,
        dns,
        subnet,
        mac,
        stack_up,
    }
}

/// Apply a **static** IPv4 configuration to the running stack. Validates every
/// field with the pure helpers, then hands the write to the privileged
/// `eos-netcfg` shim (the `netcfg:` scheme rejects non-root writers with
/// `EACCES`) with the user's `password` piped on its stdin — so the GUI never
/// runs as root. Empty `gateway`/`dns` are left unchanged. Errors (bad input,
/// bad password, no shim) are surfaced, never panicked.
pub fn apply_static(
    iface: &str,
    ip: &str,
    prefix: i32,
    gateway: &str,
    dns: &str,
    password: &str,
) -> Result<(), String> {
    let (ip, gateway, dns) = (ip.trim(), gateway.trim(), dns.trim());
    if !valid_ipv4(ip) {
        return Err(format!("nieprawidłowy adres IP: {ip}"));
    }
    if !valid_prefix(prefix) {
        return Err(format!("prefiks poza zakresem 0–32: {prefix}"));
    }
    if !gateway.is_empty() && !valid_ipv4(gateway) {
        return Err(format!("nieprawidłowy adres bramy: {gateway}"));
    }
    if !dns.is_empty() && !valid_ipv4(dns) {
        return Err(format!("nieprawidłowy adres DNS: {dns}"));
    }
    let iface = iface.trim();
    let iface = if iface.is_empty() { "eth0" } else { iface };
    apply_static_impl(iface, ip, prefix, gateway, dns, password)
}

/// Spawn `eos-netcfg <iface> <ip> <prefix> <gw|-> <dns|->`, pipe `password` to
/// its stdin, and wait. Ok = the shim authenticated and applied the config;
/// Err = bad password / no permission. Redox-only; on a host it is a guarded
/// no-op so a developer's box is never reconfigured.
#[cfg(target_os = "redox")]
fn apply_static_impl(
    iface: &str,
    ip: &str,
    prefix: i32,
    gateway: &str,
    dns: &str,
    password: &str,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // `-` tells the shim to leave that field unchanged.
    let gw = if gateway.is_empty() { "-" } else { gateway };
    let dns_arg = if dns.is_empty() { "-" } else { dns };
    let mut child = Command::new("eos-netcfg")
        .args([iface, ip, &prefix.to_string(), gw, dns_arg])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("nie można uruchomić eos-netcfg: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{password}");
    }
    match child.wait() {
        Ok(st) if st.success() => Ok(()),
        Ok(_) => Err("błędne hasło lub brak uprawnień".into()),
        Err(e) => Err(format!("eos-netcfg: {e}")),
    }
}

#[cfg(not(target_os = "redox"))]
fn apply_static_impl(
    _iface: &str,
    _ip: &str,
    _prefix: i32,
    _gateway: &str,
    _dns: &str,
    _password: &str,
) -> Result<(), String> {
    Err("dostępne tylko na E-OS".into())
}

/// Filesystem usage of the root mount, shown on the Storage tab. Sizes are in
/// bytes; `total = 0` means the query failed (degrade gracefully, never panic).
#[derive(Clone, Debug, Default)]
pub struct Storage {
    /// Total size of the root filesystem.
    pub total_bytes: u64,
    /// Space still free.
    pub free_bytes: u64,
    /// Space in use (`total - free`).
    pub used_bytes: u64,
}

/// Read root-filesystem usage via `statvfs`. On E-OS this hits redoxfs's
/// `fstatvfs` (real block counts: `f_blocks`, `f_bavail`); on a host it's the
/// POSIX `statvfs(2)`. Never panics — a failed query returns all-zero.
pub fn storage() -> Storage {
    #[cfg(target_os = "redox")]
    {
        redox_storage()
    }
    #[cfg(not(target_os = "redox"))]
    {
        host_storage()
    }
}

/// Assemble a Storage from raw statvfs block figures.
fn storage_from(f_bsize: u64, f_blocks: u64, f_bavail: u64) -> Storage {
    let total = f_blocks.saturating_mul(f_bsize);
    let free = f_bavail.saturating_mul(f_bsize);
    Storage {
        total_bytes: total,
        free_bytes: free,
        used_bytes: total.saturating_sub(free),
    }
}

/// Audio state — the master output level, shown on the Sound tab.
///
/// `audiod` serves the `audio:` scheme; its `audio:volume` control reads and
/// writes the master volume as a plain decimal string `0–100`, so we treat it as
/// an ordinary file. When `audiod` isn't running — it exits if no `audiohw:`
/// driver is present, e.g. on the QEMU dev loop where `ihdad` never completes its
/// HDA/RIRB handshake (see `docs/known-issues.md`) — the open fails and we
/// degrade to `available = false`. On a host `/scheme` is absent → same graceful
/// path. This keeps the tab honest instead of showing a slider that controls
/// nothing.
#[derive(Clone, Debug, Default)]
pub struct Audio {
    /// True when `audio:volume` could be opened — i.e. audiod is live.
    pub available: bool,
    /// Master output volume, 0–100 (meaningful only when `available`).
    pub volume: i32,
}

/// audiod's master-volume control endpoint.
const VOLUME_PATH: &str = "/scheme/audio/volume";

/// Clamp a volume to the daemon's accepted `0–100` range — audiod rejects
/// anything outside it with `EINVAL`, so we never send an out-of-range value.
pub fn clamp_volume(v: i32) -> i32 {
    v.clamp(0, 100)
}

/// Parse the decimal string audiod returns for `audio:volume` into `0–100`.
/// `None` for non-numeric input (so a garbled read can't masquerade as a level).
pub fn parse_volume(s: &str) -> Option<i32> {
    s.trim().parse::<i32>().ok().map(clamp_volume)
}

/// Read the current master volume + whether the audio stack is up. Never panics;
/// an absent/closed `audio:` scheme degrades to `available = false`. Read-only,
/// so it is safe to call from the boot self-test (it never moves the level).
pub fn audio() -> Audio {
    match std::fs::read_to_string(VOLUME_PATH) {
        Ok(s) => Audio {
            available: true,
            // Scheme answered but with garbage → up, level unknown (0).
            volume: parse_volume(&s).unwrap_or(0),
        },
        Err(_) => Audio {
            available: false,
            volume: 0,
        },
    }
}

/// Set the master volume (clamped to `0–100`). Writes the decimal string to
/// `audio:volume`; audiod applies it as a perceptual cube curve to every mixed
/// sample. Errors (e.g. audiod not running) are surfaced, never panicked.
pub fn set_volume(v: i32) -> Result<(), String> {
    let v = clamp_volume(v);
    std::fs::write(VOLUME_PATH, v.to_string().as_bytes()).map_err(|e| format!("{VOLUME_PATH}: {e}"))
}

/// Power the machine off. The control `sys:kstop` is root-only and eos-control
/// runs as the desktop user, so we hand the request to the `eos-power` shim with
/// the user's `password` piped on its stdin; the shim elevates via `/scheme/sudo`
/// and writes `sys:kstop`. See `src/power.rs`.
pub fn shutdown(password: &str) -> Result<(), String> {
    power("shutdown", password)
}

/// Reboot the machine — same privileged `eos-power` path as [`shutdown`].
pub fn reboot(password: &str) -> Result<(), String> {
    power("reboot", password)
}

/// Spawn `eos-power <action>`, pipe `password` to its stdin, and wait for it.
/// A correct password → the shim writes `sys:kstop` and the machine goes down;
/// a wrong one → the shim exits non-zero and we surface it. Redox-only; on a
/// host this is a guarded no-op so the GUI can never halt a developer's box.
#[cfg(target_os = "redox")]
fn power(action: &str, password: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("eos-power")
        .arg(action)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("nie można uruchomić eos-power: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{password}");
    }
    // eos-power is short-lived: on success it writes sys:kstop (machine down);
    // on a bad password it exits fast. Waiting lets us report a bad password
    // without leaving the button in limbo.
    match child.wait() {
        Ok(st) if st.success() => Ok(()),
        Ok(_) => Err("błędne hasło lub brak uprawnień".into()),
        Err(e) => Err(format!("eos-power: {e}")),
    }
}

#[cfg(not(target_os = "redox"))]
fn power(_action: &str, _password: &str) -> Result<(), String> {
    Err("dostępne tylko na E-OS".into())
}

#[cfg(target_os = "redox")]
fn redox_storage() -> Storage {
    use std::os::fd::AsRawFd;
    // fstatvfs needs a fd on the target filesystem; the root dir is fine.
    let Ok(dir) = std::fs::File::open("/") else {
        return Storage::default();
    };
    match libredox::call::fstatvfs(dir.as_raw_fd() as usize) {
        Ok(v) => storage_from(v.f_bsize as u64, v.f_blocks as u64, v.f_bavail as u64),
        Err(_) => Storage::default(),
    }
}

#[cfg(not(target_os = "redox"))]
fn host_storage() -> Storage {
    use std::mem::MaybeUninit;
    let mut buf = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: statvfs fills `buf` from a valid NUL-terminated path.
    let rc = unsafe { libc::statvfs(b"/\0".as_ptr().cast(), buf.as_mut_ptr()) };
    if rc != 0 {
        return Storage::default();
    }
    let v = unsafe { buf.assume_init() };
    storage_from(v.f_bsize as u64, v.f_blocks as u64, v.f_bavail as u64)
}

#[cfg(target_os = "redox")]
mod redox {
    use super::{labels, Overview, Proc};
    use std::collections::HashMap;
    use std::fs;

    pub fn overview() -> Overview {
        let procs = super::processes();
        let (cs, irqs) = stat_counters();
        Overview {
            system: system(),
            cpus: cpus(),
            processes: procs.len(),
            mem_bytes: procs.iter().map(|p| p.mem_bytes).sum(),
            context_switches: cs,
            irqs,
        }
    }

    pub fn processes() -> Vec<Proc> {
        let caps = capabilities(); // pid -> distinct open schemes
        let raw = fs::read_to_string("/scheme/sys/context").unwrap_or_default();
        raw.lines()
            .skip(1) // header row
            .filter_map(|line| {
                // Fixed-width columns (kernel formats with {:<6}/{:<11}/{:<12}/{:<8}):
                // PID<6 EUID<6 EGID<6 STAT<6 CPU<6 AFFINITY<11 TIME<12 PRIVATE<8 SHARED<8 NAME
                let col = |a: usize, b: usize| line.get(a..b).unwrap_or("").trim().to_string();
                let pid = col(0, 6);
                if pid.is_empty() {
                    return None;
                }
                let name = line.get(69..).unwrap_or("").trim().to_string();
                Some(Proc {
                    label: labels::describe(&name),
                    owner: col(6, 12),
                    status: col(18, 24),
                    cpu_time: col(41, 53),
                    memory: col(53, 61),
                    mem_bytes: super::parse_bytes(line.get(53..61).unwrap_or("")),
                    resources: caps.get(&pid).cloned().unwrap_or_default(),
                    pid,
                    name,
                })
            })
            .collect()
    }

    // `sys:uname` = "Redox\n{version}\n{arch}\n{source_ident}\n".
    fn system() -> String {
        let raw = fs::read_to_string("/scheme/sys/uname").unwrap_or_default();
        let mut l = raw.lines();
        let _ = l.next();
        let ver = l.next().unwrap_or("").trim();
        let arch = l.next().unwrap_or("").trim();
        if ver.is_empty() && arch.is_empty() {
            "E-OS".into()
        } else {
            format!("E-OS (Redox {ver}) · {arch}")
        }
    }

    fn cpus() -> u32 {
        fs::read_to_string("/scheme/sys/cpu")
            .ok()
            .and_then(|s| {
                s.lines()
                    .next()
                    .and_then(|l| l.strip_prefix("CPUs:"))
                    .and_then(|n| n.trim().parse().ok())
            })
            .unwrap_or(0)
    }

    // `sys:stat` carries "ctxt {n}" (context switches) and "intr {total} …".
    fn stat_counters() -> (u64, u64) {
        let raw = fs::read_to_string("/scheme/sys/stat").unwrap_or_default();
        let find = |key: &str| {
            raw.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0)
        };
        (find("ctxt"), find("intr").max(find("IRQs")))
    }

    // The capability inspector: `sys:iostat` lists per process ("PID: name")
    // its open fds, each ending in the resolved scheme path. Collect the distinct
    // scheme prefix of each path per pid.
    fn capabilities() -> HashMap<String, Vec<String>> {
        let raw = fs::read_to_string("/scheme/sys/iostat").unwrap_or_default();
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        let mut cur = String::new();
        for line in raw.lines() {
            // A process header line: "1234: name" (not indented, pid then colon).
            if let Some((pid, _)) = line.split_once(':') {
                if !line.starts_with(char::is_whitespace)
                    && pid.trim().bytes().all(|b| b.is_ascii_digit())
                    && !pid.trim().is_empty()
                {
                    cur = pid.trim().to_string();
                    map.entry(cur.clone()).or_default();
                    continue;
                }
            }
            // An fd line: the resolved path is the tail; its scheme is before ':'.
            if !cur.is_empty() {
                if let Some(scheme) = scheme_of(line) {
                    let v = map.entry(cur.clone()).or_default();
                    if !v.contains(&scheme) {
                        v.push(scheme);
                    }
                }
            }
        }
        map
    }

    // Extract the scheme name from an iostat fd line's trailing path. Redox paths
    // are `scheme:reference`; a "/scheme/name/…" form is normalised too.
    fn scheme_of(line: &str) -> Option<String> {
        let path = line.rsplit(": ").next()?.trim();
        if path.is_empty() {
            return None;
        }
        let s = path
            .strip_prefix("/scheme/")
            .unwrap_or(path)
            .split([':', '/'])
            .next()?
            .trim();
        if s.is_empty() || s.chars().all(|c| c.is_ascii_hexdigit()) {
            None // skip numeric-only leftovers
        } else {
            Some(s.to_string())
        }
    }
}

#[cfg(not(target_os = "redox"))]
mod host {
    use super::{labels, Overview, Proc};
    use std::fs;

    pub fn overview() -> Overview {
        let procs = super::processes();
        Overview {
            system: system(),
            cpus: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(0),
            processes: procs.len(),
            mem_bytes: procs.iter().map(|p| p.mem_bytes).sum(),
            context_switches: 0,
            irqs: 0,
        }
    }

    pub fn processes() -> Vec<Proc> {
        let Ok(rd) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                let n = e.file_name();
                let pid = n.to_str()?;
                if !pid.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let name = fs::read_to_string(format!("/proc/{pid}/comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                Some(Proc {
                    label: labels::describe(&name),
                    pid: pid.to_string(),
                    name: if name.is_empty() { "?".into() } else { name },
                    ..Default::default()
                })
            })
            .collect()
    }

    fn system() -> String {
        let ostype = fs::read_to_string("/proc/sys/kernel/ostype")
            .unwrap_or_else(|_| std::env::consts::OS.to_string());
        format!("{} · {}", ostype.trim(), std::env::consts::ARCH)
    }
}
