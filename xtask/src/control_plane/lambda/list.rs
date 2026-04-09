use color_eyre::eyre::Result;

use crate::control_plane::lambda_core;

pub(crate) fn run() -> Result<()> {
    println!("{:<20} {:<20} {:<15}", "Name", "Binary", "Crate");
    for target in lambda_core::TARGETS {
        println!(
            "{:<20} {:<20} {:<15}",
            target.name, target.binary_name, target.crate_name
        );
    }
    Ok(())
}
