# E-OS Control

The unified Crimson **control center** for [E-OS](https://gitlab.com/e-os/e-os) —
one app for system monitoring, process/task management, and security. Built on the
shared [`eos-ui`](https://gitlab.com/e-os/eos-ui) Slint-on-Orbital backend.

> **Why one app, not several?** On a capability-secure microkernel, *what a process
> can touch* (its open schemes) is at once its **resource profile** and its
> **security profile** — so monitoring and security are two views of one truth.
> Splitting them into separate tools fragments that. E-OS Control keeps them together.

## Tabs

- **Overview** — system identity, CPU count, process count, **total private memory**,
  context switches, IRQs (from `sys:uname` / `sys:cpu` / `sys:stat` / the process list).
- **Processes** — a task manager that's meant to beat the Windows one:
  - **ranked by memory** (heaviest first) so "what's eating my RAM?" is answered at a
    glance; the footer shows the process count and total private memory;
  - **grouped by app**, not scattered: many instances of one program (think a
    browser with eight windows) collapse into a single `name ×N` header with the
    summed memory and the *union* of their resources (groups rank by their summed
    total); expand it on demand instead of hunting duplicates down a flat list;
  - every process carries a **human label** ("orbital = desktop server", "pcid = PCI
    driver manager") so you're never lost in cryptic names;
  - a **capability inspector** — select a process to see exactly which schemes/
    resources it holds open (from `sys:iostat`). Impossible to show on Windows.
  - **force-kill** — select a stuck process and confirm to end it (SIGKILL, which
    relibc routes to the kernel's unblockable ForceKill via `libredox`);
  - live refresh, memory + CPU time + owner + status, and a filter.
- **Security** — a blake3 file-integrity **baseline** + diff (NEW/MODIFIED/REMOVED),
  a dangerous-permission **audit** (setuid/setgid/world-writable), a
  tamper-evident baseline digest, and a **scan-scope** check (below).
  (Ported from `eos-guard`.)
### Scan scope

The directory list is a free-text field the person edits between one scan and the
next, and the baseline now records the set it was taken over (`meta.roots`).

**A file the scan never looked for is not a file that was removed.** Baseline
`/usr/bin, /etc`, narrow the field to `/etc`, press Skanuj, and every file under
`/usr/bin` used to come back **USUNIĘTY — brak na dysku**, about a tree nothing had
opened. Clearing the field entirely condemned the whole baseline the same way. With
real roots that is thousands of rows, and a Security tab that reports thousands of
removals that did not happen is one people learn to ignore.

Those files are now **counted, not listed**, and the count reaches the status line
together with a `⚠ ZAKRES:` note naming which root was dropped or added. Counting
rather than listing is the point: a thousand rows saying *not checked* is the same
wall of noise under a politer label, and dropping them silently would be fail-open.

A **widened** scan is warned about but not filtered — every extra **NOWY** it produces
is a *true* statement ("this file is not in the baseline"), merely an uninformative
one, which is the opposite of a false USUNIĘTY.

The decision does **not** read `meta.roots`: what counts as unchecked comes from the
roots *this scan actually walked*. So a baseline written before the field existed still
diffs correctly, and rewriting `meta.roots` cannot hide a real removal — only spoil the
explanation. `meta.roots` is deliberately **not** a baseline-digest input, because
widening that input would make every baseline already on disk report **⚠ WZORZEC
NARUSZONY** after an upgrade that changed no file.

- **Network** — the **live** config read from the `netcfg:` scheme (interface, IP,
  netmask, gateway, DNS, MAC, stack status), plus a **static editor**: set the
  IP/prefix/gateway/DNS and apply them live. The write is root-only, so it goes
  through the privileged `eos-netcfg` shim (password-gated, GUI never runs as
  root — like the power actions). See `docs/design-eos-control-network.md`.
- **Storage** — root-filesystem capacity / used / free / use-% via `statvfs`
  (redoxfs `fstatvfs` on E-OS).
- **Sound** — audiod's master volume (a slider + mute over `audio:volume`); shows
  an honest "unavailable" state when no `audiohw:` driver is up.
- **Power** — reboot / shutdown, each a two-step confirm + password, via the
  privileged `eos-power` shim (`docs/design-eos-power.md`).

## Download — Linux only, and that is deliberate

E-OS Control is a **developer** build outside E-OS, not a consumer download beside Notes and
Guard. That is what `PR-008` in the roadmap says, and it is why only one archive is produced:

| system | archive | contents |
|---|---|---|
| Linux x86_64 | `eos-control-<ver>-x86_64-unknown-linux-gnu.tar.gz` | `eos-control`, `LICENSE`, `README.md` |

A `.sha256` accompanies it, taken over the archive — the file a person actually downloads.

There is **no Windows archive**, and the reason is scope rather than a compiler: the Windows work
would be the same two lines the sibling products carry. If that changes, it changes in the roadmap
first.

Three things worth knowing before running it off E-OS:

1. **The archive is not signed.** Signing product downloads needs a key a human generates and
   holds outside this repository, so a checksum is all there is. It proves the download was not
   corrupted; it does not prove who built it.
2. **fontconfig must be present at runtime.** The build deliberately `dlopen`s libfontconfig
   rather than linking it — that is what makes the cross build possible — so a system without it
   starts and then finds no fonts. Every mainstream desktop distribution has it.
3. **Half the tabs have nothing to talk to.** Control reads and writes Redox schemes:
   `/etc/net` for Network, the sudo scheme for privileged actions, `audio:volume` for Sound. On a
   Linux host those are absent, so it is a build for looking at the interface and working on it,
   not for administering the machine you run it on.

## Headless self-test

`eos-control --selftest` proves every core without a display — the system/process
snapshot, the byte-size math behind group memory sums, the security baseline/audit/
digest, **both directions of the scan-scope rule** (a narrowed scan over an untouched
tree must report zero removals and two files out of scope; a scan over the baseline's
own roots must report a genuine deletion and print nothing about scope), and the
**force-kill path** (it spawns a throwaway child, kills it, and confirms it dies) —
printing `EOS-CONTROL-SELFTEST-OK`. Used by boot probes and CI.
On a host it reads `/proc`.

## Building

Built as an E-OS recipe (`recipes/gui/eos-control`) for `aarch64/x86_64-unknown-redox`.
Bundled SQLite needs `-DSQLITE_DISABLE_LFS` (relibc has no LFS64 aliases). Host build
for development/CI: `cargo build --no-default-features` (the CLI/selftest half —
see [docs/creating-an-eos-app.md](https://gitlab.com/e-os/e-os/-/blob/main/docs/creating-an-eos-app.md)).

## Hosting

Dev + CI on GitLab (`gitlab.com/e-os/eos-control`); `github.com/Gh0s777tt/eos-control`
is the read-only mirror recipes fetch from. License: AGPL-3.0-or-later.
