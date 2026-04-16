//! Cedar policy compilation and schema generation.
//!
//! - `compile` — compile ForgeGuard policies into Cedar `permit`/`forbid`
//!   statements.
//! - `schema` — generate Cedar JSON schemas from policies, actions, and
//!   optional entity configuration.

mod compile;
mod schema;

pub use compile::{compile_all_to_cedar, compile_policy_to_cedar};
pub use schema::{generate_cedar_schema, CedarAttributeType, EntitySchemaConfig};
