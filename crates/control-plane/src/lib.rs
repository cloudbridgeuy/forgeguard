#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod app;

mod config;
mod dynamo_store;
mod error;
mod handlers;
mod store;
