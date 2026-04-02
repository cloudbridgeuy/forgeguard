//! `forgeguard keygen` — generate an Ed25519 signing keypair.

use std::path::Path;

use color_eyre::eyre::{bail, Result};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;

const PRIVATE_KEY_FILENAME: &str = "forgeguard.private.pem";
const PUBLIC_KEY_FILENAME: &str = "forgeguard.public.pem";

pub(crate) fn run(out_dir: &Path, key_id: Option<&str>, force: bool) -> Result<()> {
    if !out_dir.exists() {
        std::fs::create_dir_all(out_dir)?;
    }

    let private_path = out_dir.join(PRIVATE_KEY_FILENAME);
    let public_path = out_dir.join(PUBLIC_KEY_FILENAME);

    if !force {
        if private_path.exists() {
            bail!(
                "'{}' already exists — use --force to overwrite",
                private_path.display()
            );
        }
        if public_path.exists() {
            bail!(
                "'{}' already exists — use --force to overwrite",
                public_path.display()
            );
        }
    }

    let key_id = match key_id {
        Some(id) => id.to_string(),
        None => generate_key_id(),
    };

    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| color_eyre::eyre::eyre!("failed to encode private key: {e}"))?;
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| color_eyre::eyre::eyre!("failed to encode public key: {e}"))?;

    std::fs::write(&private_path, private_pem.as_bytes())?;
    std::fs::write(&public_path, public_pem.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600))?;
    }

    println!("Generated Ed25519 keypair:");
    println!("  Private key: {}", private_path.display());
    println!("  Public key:  {}", public_path.display());
    println!("  Key ID:      {key_id}");
    println!();
    println!("Add to your forgeguard.toml:");
    println!();
    println!("  [signing]");
    println!("  key_path = \"{}\"", private_path.display());
    println!("  key_id = \"{key_id}\"");

    Ok(())
}

fn generate_key_id() -> String {
    let date = chrono::Utc::now().format("%Y%m%d");
    let hex: String = (0..6)
        .map(|_| format!("{:x}", rand::random::<u8>() % 16))
        .collect();
    format!("fg-{date}-{hex}")
}
