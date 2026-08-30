---
title: Security policy
status: current
last-reviewed: 2026-08-30
owner: Gh0s777tt
---

# Security policy

**Do not open a public issue for a security bug.**

This repository is a component of **E-OS**. The full policy — supported versions, response targets,
scope, and the list of already-known gaps — lives in the orchestrating repository:
<https://gitlab.com/e-os/e-os/-/blob/main/SECURITY.md>.

## Reporting

1. **GitHub Security Advisories** — <https://github.com/Gh0s777tt/E-OS/security/advisories/new>
   (preferred: private thread, CVE path)
2. **Email** — `dzierzawskii98.dam@gmail.com`

No PGP key is published for this project. Do not encrypt to a key found elsewhere claiming to be ours.

## Scope for this repository

**In scope:** defects in this component's own code that affect confidentiality, integrity or
availability on a running E-OS system — including privilege handling, input parsing, and any path
where this component talks to a privileged helper.

**Out of scope:** defects in `slint`, `orbclient` or other third-party crates (report upstream);
missing features documented as absent.

## Known gap

**This repository has no automated tests.** Tracked as `S-13` in the E-OS roadmap. It is recorded
here because a reporter deserves to know what has and has not been checked.
