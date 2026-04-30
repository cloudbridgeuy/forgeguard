//! In-process [`VpClient`] for tests, with failure-injection knobs.
//!
//! Exposed at `cfg(any(test, feature = "test-support"))` so integration tests
//! can construct it. Production code paths must not depend on this type.

#![cfg(any(test, feature = "test-support"))]
#![allow(clippy::expect_used)] // Test-support: mutex poisoning is a non-recoverable test bug.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::{Error, NamedPolicy, Result};

/// Recorded interaction with the stub, used by tests to assert call ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StubCall {
    CreatePolicy {
        store_id: String,
        name: String,
    },
    DeletePolicyByName {
        store_id: String,
        name: String,
    },
    #[allow(dead_code)]
    ListPolicyIds {
        store_id: String,
    },
}

/// In-process VP stub. Methods take `&self` and use a `Mutex` for interior
/// mutability so the type can be wrapped in `Arc<dyn VpClient>` like the real
/// AWS impl.
pub(crate) struct StubVpClient {
    state: Mutex<StubState>,
}

#[derive(Default)]
struct StubState {
    /// `(store_id, name) -> policy_id`
    policies: BTreeMap<(String, String), String>,
    next_policy_id: u64,
    fail_on_create: Option<String>,
    fail_on_delete: Option<String>,
    fail_after_n_creates: Option<u64>,
    creates_so_far: u64,
    calls: Vec<StubCall>,
}

impl Default for StubVpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StubVpClient {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(StubState::default()),
        }
    }

    /// Cause the next `create_policy` call with `name` to fail with
    /// `Error::Other`. Cleared once it fires (one-shot).
    pub(crate) fn fail_on_create(&self, name: &str) {
        let mut s = self.state.lock().expect("StubVpClient mutex poisoned");
        s.fail_on_create = Some(name.to_owned());
    }

    /// Cause the next `delete_policy_by_name` call with `name` to fail with
    /// `Error::Other`. Cleared once it fires.
    // Test-support injection knob; consumers added in Wave 3A integration tests.
    #[allow(dead_code)]
    pub(crate) fn fail_on_delete(&self, name: &str) {
        let mut s = self.state.lock().expect("StubVpClient mutex poisoned");
        s.fail_on_delete = Some(name.to_owned());
    }

    /// Cause the next `create_policy` call to fail once `n` successful creates
    /// have already occurred (failed creates do not count). One-shot — cleared
    /// after firing.
    pub(crate) fn fail_after_n_creates(&self, n: u64) {
        let mut s = self.state.lock().expect("StubVpClient mutex poisoned");
        s.fail_after_n_creates = Some(n);
    }

    /// Snapshot the call log in invocation order.
    pub(crate) fn calls(&self) -> Vec<StubCall> {
        self.state
            .lock()
            .expect("StubVpClient mutex poisoned")
            .calls
            .clone()
    }
}

impl super::VpClient for StubVpClient {
    async fn create_policy(
        &self,
        store_id: &str,
        name: &str,
        _description: Option<&str>,
        _statement: &str,
    ) -> Result<String> {
        let mut s = self.state.lock().expect("StubVpClient mutex poisoned");
        s.calls.push(StubCall::CreatePolicy {
            store_id: store_id.to_owned(),
            name: name.to_owned(),
        });

        if s.fail_on_create.as_deref() == Some(name) {
            s.fail_on_create = None;
            return Err(Error::Other(format!("stub forced fail on create '{name}'")));
        }

        if let Some(threshold) = s.fail_after_n_creates {
            if s.creates_so_far >= threshold {
                s.fail_after_n_creates = None;
                return Err(Error::Other(format!(
                    "stub forced fail after {threshold} creates"
                )));
            }
        }

        let id = format!("policy-{}", s.next_policy_id);
        s.next_policy_id += 1;
        s.creates_so_far += 1;
        s.policies
            .insert((store_id.to_owned(), name.to_owned()), id.clone());
        Ok(id)
    }

    async fn delete_policy_by_name(&self, store_id: &str, name: &str) -> Result<()> {
        let mut s = self.state.lock().expect("StubVpClient mutex poisoned");
        s.calls.push(StubCall::DeletePolicyByName {
            store_id: store_id.to_owned(),
            name: name.to_owned(),
        });

        if s.fail_on_delete.as_deref() == Some(name) {
            s.fail_on_delete = None;
            return Err(Error::Other(format!("stub forced fail on delete '{name}'")));
        }

        s.policies
            .remove(&(store_id.to_owned(), name.to_owned()))
            .map(|_| ())
            .ok_or_else(|| {
                Error::NotFound(format!("policy '{name}' not found in store '{store_id}'"))
            })
    }

    async fn list_policy_ids(&self, store_id: &str) -> Result<Vec<NamedPolicy>> {
        let s = self.state.lock().expect("StubVpClient mutex poisoned");
        // BTreeMap iteration is already (store_id, name)-sorted, so the
        // resulting vec is sorted by name within the requested store.
        let out: Vec<NamedPolicy> = s
            .policies
            .iter()
            .filter(|((sid, _), _)| sid == store_id)
            .map(|((_, name), id)| NamedPolicy {
                policy_id: id.clone(),
                name: Some(name.clone()),
            })
            .collect();
        Ok(out)
    }
}

/// Convenience: a stub with no failure injection, ready to share via `Arc`.
pub(crate) fn happy_stub() -> Arc<StubVpClient> {
    Arc::new(StubVpClient::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::VpClient;
    use super::*;

    #[tokio::test]
    async fn create_then_list_then_delete() {
        let stub = StubVpClient::new();
        stub.create_policy("store-1", "admin", None, "permit(...)")
            .await
            .unwrap();
        let listed = stub.list_policy_ids("store-1").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_deref(), Some("admin"));

        stub.delete_policy_by_name("store-1", "admin")
            .await
            .unwrap();
        let listed = stub.list_policy_ids("store-1").await.unwrap();
        assert!(listed.is_empty());
    }

    #[tokio::test]
    async fn fail_on_create_one_shot() {
        let stub = StubVpClient::new();
        stub.fail_on_create("admin");
        let err = stub
            .create_policy("store-1", "admin", None, "permit(...)")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(_)));
        // Knob is cleared after firing — second call should succeed.
        stub.create_policy("store-1", "admin", None, "permit(...)")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fail_after_n_creates() {
        let stub = StubVpClient::new();
        stub.fail_after_n_creates(2);
        stub.create_policy("s", "a", None, "p").await.unwrap();
        stub.create_policy("s", "b", None, "p").await.unwrap();
        let err = stub.create_policy("s", "c", None, "p").await.unwrap_err();
        assert!(matches!(err, Error::Other(_)));
    }

    #[tokio::test]
    async fn delete_records_call_log() {
        let stub = StubVpClient::new();
        stub.create_policy("s", "x", None, "p").await.unwrap();
        stub.delete_policy_by_name("s", "x").await.unwrap();
        let calls = stub.calls();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], StubCall::CreatePolicy { .. }));
        assert!(matches!(calls[1], StubCall::DeletePolicyByName { .. }));
    }
}
