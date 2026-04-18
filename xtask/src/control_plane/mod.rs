mod cedar;
pub(crate) mod cedar_core;
pub(crate) mod cedar_io;
mod curl;
mod dev;
pub(crate) mod dynamo_local;
mod infra;
mod lambda;
pub(crate) mod lambda_core;
pub(crate) mod op;
pub(crate) mod op_core;
pub(crate) mod schema;
mod seed;
pub(crate) mod seed_core;
mod test;
mod token;

use clap::{Args, Subcommand};
use color_eyre::eyre::Result;

#[derive(Args)]
pub struct ControlPlaneArgs {
    #[command(subcommand)]
    command: ControlPlaneCommands,
}

#[derive(Subcommand)]
enum ControlPlaneCommands {
    /// Cedar policy store management
    Cedar(cedar::CedarArgs),
    /// Make an Ed25519-signed HTTP request to the control plane
    Curl(curl::CurlArgs),
    /// Start a local development environment with DynamoDB Local and the control plane
    Dev(dev::DevArgs),
    /// Infrastructure management
    Infra(infra::InfraArgs),
    /// Lambda build and deployment
    Lambda(lambda::LambdaArgs),
    /// Seed organizations and test users into DynamoDB and Cognito
    Seed(seed::SeedArgs),
    /// Run DynamoDB integration tests with automatic container management
    Test(test::TestArgs),
    /// Retrieve a JWT for a seeded test user via Cognito AdminInitiateAuth
    Token(token::TokenArgs),
}

pub async fn run(args: &ControlPlaneArgs) -> Result<()> {
    match &args.command {
        ControlPlaneCommands::Cedar(a) => cedar::run(a).await,
        ControlPlaneCommands::Curl(a) => curl::run(a).await,
        ControlPlaneCommands::Dev(a) => dev::run(a).await,
        ControlPlaneCommands::Infra(a) => infra::run(a).await,
        ControlPlaneCommands::Lambda(a) => lambda::run(a).await,
        ControlPlaneCommands::Seed(a) => seed::run(a).await,
        ControlPlaneCommands::Test(a) => test::run(a).await,
        ControlPlaneCommands::Token(a) => token::run(a).await,
    }
}
