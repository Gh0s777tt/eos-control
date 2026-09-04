//! Security core of E-OS Control (the Security tab): a blake3 file-integrity
//! baseline + a dangerous-permission audit.
//!
//! Since ROADMAP `PR-004` the engine is not a copy any more: it is the
//! `eos-fsintegrity` crate, a workspace member of the `eos-guard` repository,
//! depended on at a pinned revision (see `Cargo.toml`). This module only
//! re-exports it under the paths the rest of this crate has always used.

pub use eos_fsintegrity::{db, scan};
