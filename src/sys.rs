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
