//! Security core of E-OS Control (the Security tab): a blake3 file-integrity
//! baseline + a dangerous-permission audit. Ported from the standalone
//! `eos-guard` — see its history for the design rationale (U-089/U-090).

pub mod db;
pub mod scan;
