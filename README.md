# E-OS Control

The unified Crimson **control center** for [E-OS](https://gitlab.com/e-os/e-os) —
one app for system monitoring, process/task management, and security. Built on the
shared [`eos-ui`](https://gitlab.com/e-os/eos-ui) Slint-on-Orbital backend.

> **Why one app, not several?** On a capability-secure microkernel, *what a process
> can touch* (its open schemes) is at once its **resource profile** and its
> **security profile** — so monitoring and security are two views of one truth.
> Splitting them into separate tools fragments that. E-OS Control keeps them together.

## Tabs

- **Overview** — system identity, CPU count, process count, context switches, IRQs
  (from `sys:uname` / `sys:cpu` / `sys:stat`).
- **Processes** — a task manager that's meant to beat the Windows one:
  - every process carries a **human label** ("orbital = desktop server", "pcid = PCI
    driver manager") so you're never lost in cryptic names;
  - a **capability inspector** — select a process to see exactly which schemes/
    resources it holds open (from `sys:iostat`). Impossible to show on Windows.
  - live refresh, memory + CPU time + owner + status, and a filter.
- **Security** — a blake3 file-integrity **baseline** + diff (NEW/MODIFIED/REMOVED),
  a dangerous-permission **audit** (setuid/setgid/world-writable), and a
  tamper-evident baseline digest. (Ported from `eos-guard`.)

## Headless self-test

`eos-control --selftest` proves every read core without a display — the system/
process snapshot and the security baseline/audit/digest — printing
`EOS-CONTROL-SELFTEST-OK`. Used by boot probes and CI. On a host it reads `/proc`.

## Building

Built as an E-OS recipe (`recipes/gui/eos-control`) for `aarch64/x86_64-unknown-redox`.
Bundled SQLite needs `-DSQLITE_DISABLE_LFS` (relibc has no LFS64 aliases). Host build
for development/CI: `cargo build --no-default-features` (the CLI/selftest half —
see [docs/creating-an-eos-app.md](https://gitlab.com/e-os/e-os/-/blob/main/docs/creating-an-eos-app.md)).

## Hosting

Dev + CI on GitLab (`gitlab.com/e-os/eos-control`); `github.com/Gh0s777tt/eos-control`
is the read-only mirror recipes fetch from. License: AGPL-3.0-or-later.
