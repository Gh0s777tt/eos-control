---
title: Contributing
status: current
last-reviewed: 2026-08-30
owner: Gh0s777tt
---

# Contributing

This repository is a component of **E-OS**. The full contribution guide — environment, branch
strategy, commit format, PR checklist, review expectations and the release process — is in the
orchestrating repository:
<https://gitlab.com/e-os/e-os/-/blob/main/CONTRIBUTING.md>.

Read [`CLAUDE.md`](CLAUDE.md) before changing anything here; it is the working contract.

## What is specific to this repository

```bash
git clone https://gitlab.com/e-os/eos-control.git && cd eos-control
cargo check --no-default-features   # host builds the non-GUI half
cargo clippy --no-default-features -- -D warnings
```

The graphical half targets `*-unknown-redox` and is built by the E-OS cookbook, not on a host.
To see a change on a running system, bump this repository's pinned revision in the orchestrator's
`repos.toml` and rebuild the image.

## Before opening a merge request

- Conventional Commits, signed, DCO sign-off (`git commit -s`)
- One logical change per MR
- **Paste real command output**, not a description of it
- Update `CHANGELOG.md` in the same MR
- **Add tests.** This repository has none today; a change that adds the first ones is welcome and
  does not need to wait for permission

Source of truth is GitLab. GitHub is a read-only mirror; this repository has **no push mirror**, so
a maintainer pushes to both by hand.
