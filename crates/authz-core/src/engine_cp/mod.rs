//! Embedded Cedar engine for the control plane's own `cp:*` authorization
//! (issue #117). Pure core: no I/O, evaluates `PolicyQuery` against a
//! `Snapshot` compiled at build time from `forgeguard.toml` (see
//! `crate::cp_model`).

mod engine;
mod entities;

pub use engine::CpCedarEngine;
