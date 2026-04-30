#![deny(clippy::unwrap_used, clippy::expect_used)]

//! Lambda entry point for the saga trigger.
//!
//! Receives DynamoDB Stream events and calls `sfn:StartExecution` for each
//! saga intent record. Deliberately minimal — one API call per record.
//! See saga.md section 5.6.

use aws_lambda_events::event::dynamodb::Event;
use forgeguard_core::SagaId;
use lambda_runtime::{service_fn, Error, LambdaEvent};

#[tokio::main]
async fn main() -> Result<(), Error> {
    fg_lambdas::init_tracing();

    lambda_runtime::run(service_fn(handler)).await
}

async fn handler(event: LambdaEvent<Event>) -> Result<(), Error> {
    let state_machine_arn = std::env::var("STATE_MACHINE_ARN").ok();

    let Some(arn) = state_machine_arn.filter(|s| !s.is_empty()) else {
        tracing::warn!("STATE_MACHINE_ARN not set — skipping execution start");
        return Ok(());
    };

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let sfn = aws_sdk_sfn::Client::new(&config);

    for record in &event.payload.records {
        let Some(pk) = record.change.keys.get("PK") else {
            tracing::warn!("record missing PK key, skipping");
            continue;
        };
        let serde_dynamo::AttributeValue::S(ref pk_value) = *pk else {
            tracing::warn!("PK is not a string, skipping");
            continue;
        };
        let Ok(saga_id) = SagaId::from_pk(pk_value) else {
            tracing::debug!(pk = %pk_value, "not a saga intent record, skipping");
            continue;
        };

        let input = serde_json::to_string(&record)
            .map_err(|e| Error::from(format!("failed to serialize record: {e}")))?;

        tracing::info!(%saga_id, "starting saga execution");

        sfn.start_execution()
            .state_machine_arn(&arn)
            .name(saga_id.as_str())
            .input(&input)
            .send()
            .await
            .map_err(|e| Error::from(format!("StartExecution failed for {saga_id}: {e}")))?;
    }

    Ok(())
}
