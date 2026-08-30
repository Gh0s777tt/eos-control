# Changelog

All notable changes to this repository. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**How this file was built.** Reconstructed from `git log` on 2026-08-30. Every entry names the
commit that introduced it. This repository carries **no tags**, so all work sits under
`[Unreleased]`; it is released as part of the E-OS image, versioned by the orchestrator.

## [Unreleased]

### Added

- feat: E-OS Control v1 — unified control center (system + processes + security) ([`af7a9323d`](https://gitlab.com/e-os/eos-control/-/commit/af7a9323d), 2026-07-19)
- feat: group processes by app + confirm-gated force-kill (Processes tab) ([`fed7e32a4`](https://gitlab.com/e-os/eos-control/-/commit/fed7e32a4), 2026-07-19)
- feat(processes): rank by memory (heaviest first) + total-memory readout ([`772972018`](https://gitlab.com/e-os/eos-control/-/commit/772972018), 2026-07-19)
- feat(control): Network tab — live /etc/net config + stack status ([`301e0549c`](https://gitlab.com/e-os/eos-control/-/commit/301e0549c), 2026-07-19)
- feat(control): Storage tab — root filesystem usage via statvfs ([`847220c76`](https://gitlab.com/e-os/eos-control/-/commit/847220c76), 2026-07-19)
- feat(control): Power tab — reboot / shutdown (two-step confirm) ([`ba53163b4`](https://gitlab.com/e-os/eos-control/-/commit/ba53163b4), 2026-07-19)
- feat(control): working power actions via eos-power shim + password dialog (R-D11) ([`aa9029acb`](https://gitlab.com/e-os/eos-control/-/commit/aa9029acb), 2026-07-23)
- feat(control): Sound tab — master volume via audiod's audio:volume ([`a76d0587d`](https://gitlab.com/e-os/eos-control/-/commit/a76d0587d), 2026-07-23)
- feat(control): Network settings pane — live netcfg read + static apply (R-902) ([`9e95c3254`](https://gitlab.com/e-os/eos-control/-/commit/9e95c3254), 2026-07-24)
- feat(control): DHCP <-> static toggle; eos-netcfg gains subcommands (R-902) ([`40dc67fde`](https://gitlab.com/e-os/eos-control/-/commit/40dc67fde), 2026-07-24)

### Fixed

- fix(control): power actions via sudo — a user-level GUI can't write sys:kstop ([`bc216319f`](https://gitlab.com/e-os/eos-control/-/commit/bc216319f), 2026-07-19)
- fix(control): honest power-action status (no false "rebooting") ([`2c043b43b`](https://gitlab.com/e-os/eos-control/-/commit/2c043b43b), 2026-07-23)
- fix(control): read netcfg via explicit read loop, not read_to_string (R-902) ([`692050e3b`](https://gitlab.com/e-os/eos-control/-/commit/692050e3b), 2026-07-24)
- fix(control): persist static apply to /etc/net/* so the GUI reflects it (R-902) ([`5a0c6d361`](https://gitlab.com/e-os/eos-control/-/commit/5a0c6d361), 2026-07-24)
