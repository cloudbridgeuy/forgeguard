#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod app;

mod config;
mod dynamo_store;
mod error;
pub(crate) mod etag;
mod handlers;
mod signing_key;
mod store;
