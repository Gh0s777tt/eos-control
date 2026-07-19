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
/// Reads the `/etc/net/*` files the base image ships (dhcpd keeps them current)
/// and probes the scheme list to tell whether the TCP/IP stack is up. These are
/// plain file/dir reads, identical on E-OS and on a host — on a host the files
/// are absent so every field simply degrades to empty / `stack_up = false`.
#[derive(Clone, Debug, Default)]
pub struct Net {
    /// Interface address, from `/etc/net/ip` (e.g. `10.0.2.15`).
    pub ip: String,
    /// Default gateway, from `/etc/net/ip_router`.
    pub gateway: String,
    /// DNS resolver, from `/etc/net/dns`.
    pub dns: String,
    /// Subnet mask, from `/etc/net/ip_subnet`.
    pub subnet: String,
    /// True when the `ip` scheme is present — i.e. netstack/smolnetd is running.
    pub stack_up: bool,
}

/// Read the current network configuration + stack status. Never panics; any
/// unreadable source degrades to empty / `false`.
pub fn net() -> Net {
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default().trim().to_string();
    // The `ip` scheme only appears once netstack has registered it; listing
    // `/scheme` is the reliable probe (statting `/scheme/ip` directly is a
    // socket op, not a file op). On a host `/scheme` is absent → false.
    let stack_up = std::fs::read_dir("/scheme")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .any(|e| e.file_name() == "ip")
        })
        .unwrap_or(false);
    Net {
        ip: read("/etc/net/ip"),
        gateway: read("/etc/net/ip_router"),
        dns: read("/etc/net/dns"),
        subnet: read("/etc/net/ip_subnet"),
        stack_up,
    }
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
