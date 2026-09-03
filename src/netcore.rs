//! Network primitives shared by E-OS Control's GUI half (`sys.rs`) and the
//! privileged `eos-netcfg` shim (`netcfg.rs`).
//!
//! Both halves need the same parsing and the same view of what a "mode" is, and
//! the shim is a **separate binary** that can't reach the GUI crate's modules —
//! so rather than let the two drift apart, everything they share lives here and
//! each side pulls in this one file (CLAUDE.md §6: shared code over copies).
//!
//! Everything is dependency-free and — except [`read_netcfg`] — pure, which is
//! what lets `--selftest` prove it headlessly on a host that has neither the
//! `netcfg:` scheme nor `/etc/net`.

/// Where the persisted addressing **policy** lives (`dhcp` or `static`).
///
/// The `netcfg:` scheme exposes no mode node — it only holds the *result* of a
/// configuration, not how it was obtained — so the policy needs its own marker.
/// `/etc/net/` is already the GUI's read surface and netstack only reads the
/// specific keys it knows, so an extra file here is inert to everything else.
pub const NET_MODE_PATH: &str = "/etc/net/mode";

/// How the interface gets its address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetMode {
    /// Leased from a DHCP server (the default — `10_dhcpd.service` runs at boot).
    #[default]
    Dhcp,
    /// Fixed address configured by the user.
    Static,
}

impl NetMode {
    /// The token written to [`NET_MODE_PATH`].
    pub fn as_str(self) -> &'static str {
        match self {
            NetMode::Dhcp => "dhcp",
            NetMode::Static => "static",
        }
    }

    /// Human label for the Sieć tab.
    pub fn label(self) -> &'static str {
        match self {
            NetMode::Dhcp => "Automatyczna (DHCP)",
            NetMode::Static => "Statyczna",
        }
    }
}

/// Parse the mode marker. Anything that isn't exactly `static` — including an
/// absent, empty or garbled marker — reads as **DHCP**, because that is the
/// truth on an unmarked system: `10_dhcpd.service` runs on every boot, so a box
/// nobody has configured *is* DHCP-configured. Never guesses "unknown".
pub fn parse_net_mode(s: &str) -> NetMode {
    if s.trim().eq_ignore_ascii_case("static") {
        NetMode::Static
    } else {
        NetMode::Dhcp
    }
}

/// Read the mode marker from `path` (parameterised so the self-test can point it
/// at a temp file and prove the read path, not just the parser). An unreadable
/// file degrades to [`NetMode::Dhcp`], per [`parse_net_mode`].
pub fn read_net_mode_at(path: &str) -> NetMode {
    match std::fs::read_to_string(path) {
        Ok(s) => parse_net_mode(&s),
        Err(_) => NetMode::Dhcp,
    }
}

/// Read a single-line `netcfg:` value, mapping smolnetd's placeholder strings
/// ("Not configured", "Device not found") and unreadable/empty results to
/// `None`, so a placeholder can never masquerade as a real value.
///
/// Uses an explicit `File::open` + `read` loop rather than
/// `std::fs::read_to_string`: on E-OS the latter **fails** on `netcfg:` scheme
/// files (`read_to_end`'s size-hinted specialization doesn't fit a scheme), which
/// is what made the GUI silently fall back to `/etc/net/*` in U-112. A plain read
/// loop is exactly what `cat` does, and `cat` reads these paths correctly.
pub fn read_netcfg(path: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(_) => return None,
        }
    }
    let s = String::from_utf8_lossy(&out);
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

/// Convert a dotted netmask to a prefix length (`255.255.255.0` → `24`). `None`
/// if it isn't a canonical mask (contiguous ones followed by zeros) — used to
/// pre-fill the edit form, so a weird mask just leaves the box blank.
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

/// True if `s` parses as an IPv4 address.
pub fn valid_ipv4(s: &str) -> bool {
    s.trim().parse::<std::net::Ipv4Addr>().is_ok()
}

/// True if `p` is a valid IPv4 prefix length (0–32).
pub fn valid_prefix(p: i32) -> bool {
    (0..=32).contains(&p)
}

/// True for a plausible interface name: 1–15 chars, ASCII alphanumeric plus
/// `-`/`_`.
///
/// This one earns its keep on the security side: the name rides on argv into a
/// **root** process and is interpolated into a `netcfg:` node path, so rejecting
/// `/`, `.` and whitespace here stops a crafted name from escaping the intended
/// node (`ifaces/<iface>/addr/set`). Checked by the GUI *and* re-checked by the
/// shim — the shim is the half that runs as root, so it can't trust its caller.
pub fn valid_iface(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 15
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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
