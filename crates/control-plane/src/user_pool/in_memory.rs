//! In-memory `UserPoolClient` for control-plane tests.
//!
//! Mimics Cognito by storing `(pool_id, email) → sub` rows in a `BTreeMap`.
//! Failure injection knobs (`arm_*_once`) let saga driver tests reproduce
//! transient/permanent SDK paths without an AWS round trip.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use forgeguard_authn_core::user_pool::{CreateUserParams, PoolId, UpdatePoolParams, UserPoolError};
use forgeguard_core::UserId;
use tokio::sync::RwLock;
use ulid::Ulid;

use crate::user_pool::UserPoolClient;

/// Test stub that emulates the `UserPoolClient` surface in-process.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct InMemoryUserPoolClient {
    users: RwLock<BTreeMap<(PoolId, String), UserId>>,
    fail_create: Mutex<Option<UserPoolError>>,
    fail_delete: Mutex<Option<UserPoolError>>,
    fail_get: Mutex<Option<UserPoolError>>,
    fail_update_pool: Mutex<Option<UserPoolError>>,
}

#[allow(dead_code)]
impl InMemoryUserPoolClient {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Arm a one-shot failure for the next `admin_create_user` call.
    pub(crate) fn arm_admin_create_user_once(&self, err: UserPoolError) {
        Self::arm_slot(&self.fail_create, err);
    }

    /// Arm a one-shot failure for the next `admin_delete_user` call.
    pub(crate) fn arm_admin_delete_user_once(&self, err: UserPoolError) {
        Self::arm_slot(&self.fail_delete, err);
    }

    /// Arm a one-shot failure for the next `admin_get_user` call.
    pub(crate) fn arm_admin_get_user_once(&self, err: UserPoolError) {
        Self::arm_slot(&self.fail_get, err);
    }

    /// Arm a one-shot failure for the next `update_user_pool` call.
    pub(crate) fn arm_update_user_pool_once(&self, err: UserPoolError) {
        Self::arm_slot(&self.fail_update_pool, err);
    }

    fn arm_slot(slot: &Mutex<Option<UserPoolError>>, err: UserPoolError) {
        // Poison-recovery: a panic mid-test should still let other tests arm
        // failures rather than cascading into more panics.
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(err);
    }

    fn take_slot(slot: &Mutex<Option<UserPoolError>>) -> Option<UserPoolError> {
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.take()
    }
}

#[async_trait]
impl UserPoolClient for InMemoryUserPoolClient {
    async fn admin_create_user(&self, params: CreateUserParams) -> Result<UserId, UserPoolError> {
        if let Some(err) = Self::take_slot(&self.fail_create) {
            return Err(err);
        }
        let key = (params.pool_id.clone(), params.email.clone());
        let mut users = self.users.write().await;
        if users.contains_key(&key) {
            return Err(UserPoolError::UsernameExists);
        }
        let sub = UserId::new(Ulid::new().to_string().to_lowercase()).map_err(|e| {
            UserPoolError::Permanent {
                source: Box::new(e),
            }
        })?;
        users.insert(key, sub.clone());
        Ok(sub)
    }

    async fn admin_delete_user(&self, pool_id: &PoolId, sub: &UserId) -> Result<(), UserPoolError> {
        if let Some(err) = Self::take_slot(&self.fail_delete) {
            return Err(err);
        }
        let mut users = self.users.write().await;
        let key = users
            .iter()
            .find(|(k, v)| &k.0 == pool_id && *v == sub)
            .map(|(k, _)| k.clone());
        match key {
            Some(k) => {
                users.remove(&k);
                Ok(())
            }
            // Compensation must treat not-found as idempotent success per
            // `UserPoolClient::admin_delete_user` contract.
            None => Ok(()),
        }
    }

    async fn admin_get_user(&self, pool_id: &PoolId, email: &str) -> Result<UserId, UserPoolError> {
        if let Some(err) = Self::take_slot(&self.fail_get) {
            return Err(err);
        }
        let users = self.users.read().await;
        users
            .get(&(pool_id.clone(), email.to_owned()))
            .cloned()
            .ok_or(UserPoolError::UserNotFound)
    }

    async fn update_user_pool(&self, _params: UpdatePoolParams) -> Result<(), UserPoolError> {
        if let Some(err) = Self::take_slot(&self.fail_update_pool) {
            return Err(err);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn params(pool: &str, email: &str) -> CreateUserParams {
        CreateUserParams {
            pool_id: PoolId::try_new(pool).unwrap(),
            email: email.to_owned(),
            attributes: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn create_then_get_returns_same_sub() {
        let client = InMemoryUserPoolClient::new();
        let sub = client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .unwrap();
        let fetched = client
            .admin_get_user(
                &PoolId::try_new("us-east-2_pool").unwrap(),
                "alice@example.com",
            )
            .await
            .unwrap();
        assert_eq!(fetched, sub);
    }

    #[tokio::test]
    async fn duplicate_create_returns_username_exists() {
        let client = InMemoryUserPoolClient::new();
        client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .unwrap();
        let err = client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, UserPoolError::UsernameExists));
    }

    #[tokio::test]
    async fn delete_then_get_returns_user_not_found() {
        let client = InMemoryUserPoolClient::new();
        let sub = client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .unwrap();
        client
            .admin_delete_user(&PoolId::try_new("us-east-2_pool").unwrap(), &sub)
            .await
            .unwrap();
        let err = client
            .admin_get_user(
                &PoolId::try_new("us-east-2_pool").unwrap(),
                "alice@example.com",
            )
            .await
            .unwrap_err();
        assert!(matches!(err, UserPoolError::UserNotFound));
    }

    #[tokio::test]
    async fn delete_missing_user_is_idempotent_ok() {
        let client = InMemoryUserPoolClient::new();
        let sub = UserId::new("missing").unwrap();
        client
            .admin_delete_user(&PoolId::try_new("us-east-2_pool").unwrap(), &sub)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn armed_create_failure_fires_once_then_clears() {
        let client = InMemoryUserPoolClient::new();
        client.arm_admin_create_user_once(UserPoolError::UsernameExists);
        let err = client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .unwrap_err();
        assert!(matches!(err, UserPoolError::UsernameExists));
        client
            .admin_create_user(params("us-east-2_pool", "alice@example.com"))
            .await
            .expect("second call must succeed after one-shot drains");
    }
}
