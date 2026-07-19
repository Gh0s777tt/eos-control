//! Human-readable descriptions of the processes a user is likely to see.
//!
//! Windows Task Manager's biggest usability failure is cryptic process names —
//! you can't tell what `svchost.exe` *is*. E-OS Control annotates every known
//! system process so the user always knows what it does. Matching is on the
//! basename (the kernel `sys:context` NAME is a path or a short name).

/// A short "what is this" for a process name. Returns `""` when unknown (the UI
/// then just shows the raw name).
pub fn describe(name: &str) -> String {
    // Reduce "/scheme/initfs/bin/pcid" or "/usr/lib/drivers/e1000d" to "pcid".
    let base = name
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('[')
        .trim_end_matches(']');

    let d = match base {
        "kmain" | "bootstrap" | "kernel" => "kernel — the E-OS microkernel",
        "init" | "initfs" => "init — brings up the system",
        "pcid" => "PCI driver manager — probes devices, binds drivers",
        "orbital" => "desktop server — compositor + window manager",
        "orblogin" => "graphical login (greeter)",
        "launcher" => "desktop taskbar + app launcher",
        "background" => "desktop wallpaper / background",
        "vesad" | "fbcond" => "display / framebuffer console driver",
        "inputd" => "input router — keyboard/mouse to the active console",
        "nvmed" => "NVMe storage driver",
        "ahcid" => "SATA/AHCI storage driver",
        "usbhidd" => "USB keyboard/mouse (HID) driver",
        "usbscsid" => "USB mass-storage driver",
        "xhcid" => "USB xHCI host controller driver",
        "e1000d" | "rtl8139d" | "rtl8168d" | "ixgbed" => "Ethernet NIC driver",
        "virtio-netd" | "usbnetd" => "virtual/USB network driver",
        "smolnetd" | "netstack" => "network stack (TCP/IP)",
        "dnsd" => "DNS resolver",
        "dhcpd" => "DHCP client — obtains an IP address",
        "randd" => "random-number daemon (entropy)",
        "rtcd" => "real-time clock daemon",
        "audiod" | "ihdad" | "ac97d" => "audio driver",
        "logd" | "ramfs" => "system log / ramfs service",
        "redoxfs" => "RedoxFS filesystem daemon",
        "ion" | "sh" => "shell",
        "getty" | "login" => "login prompt",
        "eos-notes" => "E-OS Notes",
        "eos-guard" => "E-OS Guard (integrity monitor)",
        "eos-sysmon" | "eos-control" => "E-OS Control (this app)",
        "eos-settings" => "E-OS Settings",
        _ => "",
    };
    d.to_string()
}
