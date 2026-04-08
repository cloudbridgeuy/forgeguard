use color_eyre::eyre::Result;

use crate::control_plane::op;
use crate::control_plane::op_core::ForgeguardEnv;

pub(crate) async fn run(env: ForgeguardEnv, op_account: Option<&str>) -> Result<()> {
    // 1. Preflight
    op::run_preflight()?;

    // 2. Ensure node_modules
    op::ensure_node_modules("infra/control-plane")?;

    // 3. Run CDK diff
    op::run_cdk_with_op(".env", env, &["diff"], op_account)?;

    Ok(())
}
