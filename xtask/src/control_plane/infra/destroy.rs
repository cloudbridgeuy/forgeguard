use color_eyre::eyre::Result;

use crate::control_plane::op;
use crate::control_plane::op_core::{self, ForgeguardEnv};

pub(crate) async fn run(env: ForgeguardEnv, op_account: Option<&str>) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;

    // 2. Warning
    let stack_name = op_core::build_stack_name(env);
    println!("WARNING: This will destroy all resources in stack '{stack_name}'.");
    println!("This action cannot be undone.\n");

    // 3. Confirmation prompt
    print!("Type 'destroy' to confirm: ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !op_core::confirm_destroy(&input) {
        println!("Aborted.");
        return Ok(());
    }

    // 4. Run CDK destroy
    op::ensure_node_modules("infra/control-plane")?;
    op::run_cdk_with_op(".env", env, &["destroy", "--force"], op_account)?;

    println!("Stack '{stack_name}' destroyed.");
    Ok(())
}
