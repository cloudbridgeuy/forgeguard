//! Compiles the repo-root `forgeguard.toml` (the control plane's own
//! authorization model) into Cedar policy text at build time. A model
//! error fails the build — a bad model can never reach a deploy.

use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let model_path = Path::new(&manifest_dir).join("../../forgeguard.toml");
    println!("cargo::rerun-if-changed={}", model_path.display());

    let toml_text = match std::fs::read_to_string(&model_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot read {}: {e}", model_path.display());
            std::process::exit(1);
        }
    };
    let cedar_text = match forgeguard_authz_core::compile_cp_model(&toml_text) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("forgeguard.toml authz model error: {e}");
            std::process::exit(1);
        }
    };
    let out = Path::new(&std::env::var("OUT_DIR").unwrap_or_default()).join("cp_policies.cedar");
    if let Err(e) = std::fs::write(&out, cedar_text) {
        eprintln!("cannot write {}: {e}", out.display());
        std::process::exit(1);
    }
}
