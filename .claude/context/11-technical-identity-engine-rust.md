# ForgeGate — Identity Engine: Technical Design

> Rust backend with type-state encoded state machines for every Cognito authentication flow.

---

## Why Rust, Why State Machines

### Rust

The Identity Engine is the security-critical core of ForgeGate. It handles token validation, credential verification, and session management — operations where memory safety bugs become CVEs. Rust eliminates an entire class of vulnerabilities (buffer overflows, use-after-free, data races) at compile time.

Beyond safety, Rust's type system enables the core architectural pattern: **typestate-encoded state machines** where invalid authentication flow transitions are compile-time errors, not runtime checks.

### State Machines for Cognito

Every Cognito authentication flow is a state machine, but Cognito's API hides this behind a generic `InitiateAuth` / `RespondToAuthChallenge` loop with string-typed challenge names and untyped parameter maps. This leads to:

- Runtime errors when challenge responses are malformed
- Silent failures when flows are composed incorrectly
- No compile-time guarantees about valid transitions
- Difficult-to-test flows with hidden intermediate states

By modeling each flow as an explicit state machine with typestate encoding, we get:

- **Compile-time guarantees** that flows can only transition through valid states
- **Exhaustive match** on every state — no forgotten edge cases
- **Self-documenting code** — the types ARE the documentation of what transitions are possible
- **Testability** — each state and transition is individually testable
- **Auditability** — security reviewers can read the state machine and verify correctness

---

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│  ForgeGate Control Plane API (Rust)                             │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  API Layer (axum)                                          │ │
│  │  Routes, middleware, request/response types                 │ │
│  └─────────────┬─────────────────────────────────────────────┘ │
│                │                                                │
│  ┌─────────────▼─────────────────────────────────────────────┐ │
│  │  Identity Engine                                           │ │
│  │                                                            │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  Flow Orchestrator                                    │ │ │
│  │  │  Selects and drives the correct                       │ │ │
│  │  │  state machine for each auth request                  │ │ │
│  │  └────────────┬─────────────────────────────────────────┘ │ │
│  │               │                                            │ │
│  │  ┌────────────▼────────────────────────┬────────────────┐ │ │
│  │  │  State Machines                     │  Event Log     │ │ │
│  │  │  (typestate encoded)                │  (append-only) │ │ │
│  │  │                                     │                │ │ │
│  │  │  PasswordFlow<S>       every ──────►│  Transition    │ │ │
│  │  │  MagicLinkFlow<S>      transition   │  events with   │ │ │
│  │  │  SmsCodeFlow<S>        records ────►│  timestamps,   │ │ │
│  │  │  OidcFlow<S>           to the ─────►│  durations,    │ │ │
│  │  │  PasskeyFlow<S>        event log    │  and context   │ │ │
│  │  │  MfaChallengeFlow<S>                │                │ │ │
│  │  │  PasswordResetFlow<S>               │  ┌──────────┐ │ │ │
│  │  │  SignUpFlow<S>                      │  │ Metrics  │ │ │ │
│  │  │                                     │  │ Emitter  │ │ │ │
│  │  └────────────┬────────────────────────┴──┴──────────┘ │ │
│  │               │                                         │ │
│  │  ┌────────────▼──────────────────────────────────────┐  │ │
│  │  │  Cognito Adapter                                   │  │ │
│  │  │  Translates state transitions into                 │  │ │
│  │  │  Cognito API calls                                 │  │ │
│  │  └────────────┬──────────────────────────────────────┘  │ │
│  │               │                                         │ │
│  │  ┌────────────▼──────────────────────────────────────┐  │ │
│  │  │  Side Effect Executor                              │  │ │
│  │  │  SES (emails), SNS (SMS), DynamoDB                 │  │ │
│  │  │  (challenge codes), Lambda (triggers)              │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  │                                                         │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │  Config Reconciler                                │  │ │
│  │  │  Declarative config → Cognito desired             │  │ │
│  │  │  state → diff → apply (also event-logged)         │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Event Log Storage (append-only)                         │ │
│  │  DynamoDB / S3 — immutable, partitioned by flow_id       │ │
│  ├─────────────────────────────────────────────────────────┤ │
│  │  Metrics Pipeline                                        │ │
│  │  CloudWatch / Prometheus — per-transition histograms      │ │
│  ├─────────────────────────────────────────────────────────┤ │
│  │  Model Engine │ Authorization Engine │ Webhook Dispatcher │ │
│  │  Test Generator                                          │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## Typestate Pattern in Rust

The typestate pattern uses Rust's type system to encode the current state of a flow as a type parameter. Transitions consume the current state and produce a new state. You literally cannot call a method that's invalid for the current state — the compiler rejects it.

### Core Traits and Types

```rust
/// Marker trait for all authentication flow states.
/// Sealed so external code cannot create invalid states.
pub trait AuthState: private::Sealed {
    /// The name of this state, used in event logs and metrics.
    fn state_name() -> &'static str;

    /// Maximum time the flow can remain in this state before
    /// it is considered abandoned and forcibly terminated.
    /// Returns None for terminal states (no timeout needed).
    fn state_timeout() -> Option<Duration>;
}

/// The result of a state transition.
/// Each transition either advances the flow or terminates it.
pub enum Transition<NextState, Terminal> {
    Continue(NextState),
    Complete(Terminal),
    Failed(AuthError),
}

/// Terminal result of any authentication flow.
pub struct AuthSuccess {
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub tokens: TokenSet,
    pub session: Session,
}

pub struct TokenSet {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: String,
    pub expires_in: Duration,
}

/// Timeout configuration for a flow type.
/// Flow-level timeout caps the entire authentication attempt.
/// Per-state timeouts cap how long each intermediate state can wait.
pub struct FlowTimeouts {
    /// Max total lifetime for the entire flow (all states combined).
    pub flow_max_lifetime: Duration,
    /// Override per-state timeouts from a config (dashboard-configurable).
    /// If None, uses the AuthState::state_timeout() defaults.
    pub state_overrides: HashMap<&'static str, Duration>,
}

impl FlowTimeouts {
    /// Resolve the effective timeout for a given state.
    pub fn effective_state_timeout<S: AuthState>(&self) -> Option<Duration> {
        self.state_overrides
            .get(S::state_name())
            .copied()
            .or_else(|| S::state_timeout())
    }

    /// Check whether the overall flow has exceeded its max lifetime.
    pub fn flow_expired(&self, started_at: Instant) -> bool {
        started_at.elapsed() > self.flow_max_lifetime
    }
}

/// Default timeouts per flow type.
impl FlowTimeouts {
    pub fn password() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(300),  // 5 min total
            state_overrides: HashMap::new(),
        }
    }
    pub fn magic_link() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(900),  // 15 min total
            state_overrides: HashMap::new(),
        }
    }
    pub fn sms_code() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(600),  // 10 min total
            state_overrides: HashMap::new(),
        }
    }
    pub fn oidc() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(600),  // 10 min total
            state_overrides: HashMap::new(),
        }
    }
    pub fn password_reset() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(3600), // 1 hour total
            state_overrides: HashMap::new(),
        }
    }
    pub fn signup() -> Self {
        Self {
            flow_max_lifetime: Duration::from_secs(3600), // 1 hour total
            state_overrides: HashMap::new(),
        }
    }
}

/// Every flow carries its context, event log, and timeout through transitions.
pub struct FlowContext {
    pub flow_id: FlowId,
    pub started_at: Instant,
    pub client_ip: IpAddr,
    pub user_agent: String,
    pub project_id: ProjectId,
    pub tenant_id: Option<TenantId>,
    pub event_log: FlowEventLog,
    pub metrics: MetricsEmitter,
    pub timeouts: FlowTimeouts,
    /// When the current state was entered. Reset on each transition.
    pub current_state_entered_at: Instant,
}

impl FlowContext {
    /// Check if the flow has exceeded its total lifetime.
    pub fn is_flow_expired(&self) -> bool {
        self.timeouts.flow_expired(self.started_at)
    }

    /// Check if the current state has exceeded its timeout.
    pub fn is_state_expired<S: AuthState>(&self) -> bool {
        match self.timeouts.effective_state_timeout::<S>() {
            Some(timeout) => self.current_state_entered_at.elapsed() > timeout,
            None => false, // No timeout for this state
        }
    }

    /// Time remaining before the current state expires. None if no timeout.
    pub fn state_time_remaining<S: AuthState>(&self) -> Option<Duration> {
        self.timeouts.effective_state_timeout::<S>().map(|timeout| {
            timeout.saturating_sub(self.current_state_entered_at.elapsed())
        })
    }

    /// Time remaining before the overall flow expires.
    pub fn flow_time_remaining(&self) -> Duration {
        self.timeouts.flow_max_lifetime
            .saturating_sub(self.started_at.elapsed())
    }

    /// Mark the entry into a new state (resets the state timer).
    pub fn enter_state(&mut self) {
        self.current_state_entered_at = Instant::now();
    }
}
```

---

## Event Log & Metrics Infrastructure

Every state machine transition is recorded in an append-only event log and emits timing metrics. This is not optional instrumentation — it's baked into the transition machinery so that every flow is fully traceable by construction.

### Event Log Design

```rust
/// Append-only event log for a single authentication flow.
/// Carried through the flow context, written to durable storage
/// on flow completion (success or failure).
pub struct FlowEventLog {
    flow_id: FlowId,
    events: Vec<TransitionEvent>,
}

/// A single recorded transition event. Immutable once created.
#[derive(Clone, Serialize)]
pub struct TransitionEvent {
    /// Monotonically increasing sequence within this flow.
    pub sequence: u64,

    /// Wall-clock time when the transition started.
    pub timestamp: DateTime<Utc>,

    /// Which flow type (password, magic_link, oidc, etc.)
    pub flow_type: &'static str,

    /// State before the transition.
    pub from_state: &'static str,

    /// State after the transition (or "failed").
    pub to_state: &'static str,

    /// Name of the transition method invoked.
    pub transition: &'static str,

    /// How long the transition took to execute.
    pub duration: Duration,

    /// Contextual metadata (no secrets — never log passwords or tokens).
    pub metadata: TransitionMetadata,

    /// Whether an external side effect occurred.
    pub side_effects: Vec<SideEffectRecord>,

    /// If the transition failed, the error classification.
    pub error: Option<TransitionError>,
}

#[derive(Clone, Serialize)]
pub struct TransitionMetadata {
    /// Redacted identifier — enough to correlate, not enough to identify.
    /// e.g., "j***@example.com" for emails, "user_***456" for IDs.
    pub principal_hint: Option<String>,

    /// Which auth method is in play.
    pub auth_method: Option<String>,

    /// MFA method if applicable.
    pub mfa_method: Option<String>,

    /// OIDC provider name if applicable.
    pub provider: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct SideEffectRecord {
    pub effect_type: SideEffectType,
    pub target: String,           // e.g., "SES", "SNS", "DynamoDB", "Cognito"
    pub operation: String,        // e.g., "SendEmail", "InitiateAuth"
    pub duration: Duration,
    pub success: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Serialize)]
pub enum SideEffectType {
    CognitoApiCall,
    EmailSent,
    SmsSent,
    ChallengeStored,
    ChallengeVerified,
    TokenGenerated,
    UserProvisioned,
}

#[derive(Clone, Serialize)]
pub struct TransitionError {
    pub kind: ErrorKind,
    pub message: String,
    pub retryable: bool,
}

#[derive(Clone, Serialize)]
pub enum ErrorKind {
    InvalidCredentials,
    InvalidCode,
    CodeExpired,
    MfaFailed,
    ProviderError,
    RateLimited,
    InternalError,
    UserNotFound,
    UserDisabled,
    Timeout,
    ManualKill,
}

impl FlowEventLog {
    pub fn new(flow_id: FlowId) -> Self {
        Self { flow_id, events: Vec::with_capacity(8) }
    }

    /// Append a transition event. Append-only — no mutation or deletion.
    pub fn record(&mut self, event: TransitionEvent) {
        debug_assert!(
            self.events.last().map_or(0, |e| e.sequence) < event.sequence,
            "Event sequence must be monotonically increasing"
        );
        self.events.push(event);
    }

    /// Snapshot the full log. Used for persistence and debugging.
    pub fn events(&self) -> &[TransitionEvent] {
        &self.events
    }

    /// Total wall-clock time from first to last event.
    pub fn total_duration(&self) -> Duration {
        match (self.events.first(), self.events.last()) {
            (Some(first), Some(last)) => {
                let end = last.timestamp + chrono::Duration::from_std(last.duration).unwrap();
                (end - first.timestamp).to_std().unwrap_or_default()
            }
            _ => Duration::ZERO,
        }
    }
}
```

### The Transition Recorder

Every state machine transition goes through the `TransitionRecorder`. It wraps the actual transition function, captures timing, records the event, and emits metrics. This is enforced structurally — the transition methods use the recorder, not the other way around.

```rust
/// Records a state machine transition: timing, event log, metrics.
/// Enforces flow-level and per-state timeouts before executing.
/// Used by every flow's transition methods.
pub struct TransitionRecorder<'a> {
    ctx: &'a mut FlowContext,
    flow_type: &'static str,
    from_state: &'static str,
    transition_name: &'static str,
}

impl<'a> TransitionRecorder<'a> {
    pub fn new(
        ctx: &'a mut FlowContext,
        flow_type: &'static str,
        from_state: &'static str,
        transition_name: &'static str,
    ) -> Self {
        Self { ctx, flow_type, from_state, transition_name }
    }

    /// Execute a transition, enforcing timeouts, recording the event,
    /// and emitting metrics.
    ///
    /// Timeout checks happen BEFORE the transition runs:
    /// 1. Check flow-level timeout (total lifetime exceeded?)
    /// 2. Check per-state timeout (been in this state too long?)
    ///
    /// If either timeout has fired, the transition is NOT executed.
    /// Instead, a timeout event is recorded and AuthError::Timeout returned.
    pub async fn execute<F, Fut, T>(
        self,
        to_state: &'static str,
        metadata: TransitionMetadata,
        f: F,
    ) -> Result<T, AuthError>
    where
        F: FnOnce(SideEffectCollector) -> Fut,
        Fut: std::future::Future<Output = Result<(T, Vec<SideEffectRecord>), AuthError>>,
    {
        // ── Enforce flow-level timeout ──
        if self.ctx.is_flow_expired() {
            let duration = self.ctx.started_at.elapsed();
            self.record_timeout_event(
                "flow_timeout",
                &metadata,
                duration,
            );
            self.ctx.metrics.counter(
                "forgegate.identity.timeout.count",
                1,
                &[
                    ("flow_type", self.flow_type),
                    ("state", self.from_state),
                    ("timeout_type", "flow"),
                ],
            );
            return Err(AuthError::FlowTimeout {
                flow_id: self.ctx.flow_id.clone(),
                elapsed: duration,
                max_lifetime: self.ctx.timeouts.flow_max_lifetime,
            });
        }

        // ── Enforce per-state timeout ──
        let state_elapsed = self.ctx.current_state_entered_at.elapsed();
        if let Some(state_timeout) = self.ctx.timeouts
            .state_overrides
            .get(self.from_state)
            .copied()
            // Fall back to checking if it was provided by the caller context
            // (we can't call S::state_timeout() here without the type,
            //  so the flow method passes it through FlowContext at state entry)
        {
            if state_elapsed > state_timeout {
                self.record_timeout_event(
                    "state_timeout",
                    &metadata,
                    state_elapsed,
                );
                self.ctx.metrics.counter(
                    "forgegate.identity.timeout.count",
                    1,
                    &[
                        ("flow_type", self.flow_type),
                        ("state", self.from_state),
                        ("timeout_type", "state"),
                    ],
                );
                return Err(AuthError::StateTimeout {
                    flow_id: self.ctx.flow_id.clone(),
                    state: self.from_state.to_string(),
                    elapsed: state_elapsed,
                    max_duration: state_timeout,
                });
            }
        }

        // ── Execute the actual transition ──
        let start = Instant::now();
        let timestamp = Utc::now();
        let seq = self.ctx.event_log.events.len() as u64;

        let collector = SideEffectCollector::new();
        let result = f(collector).await;

        let duration = start.elapsed();
        let (side_effects, error) = match &result {
            Ok((_, effects)) => (effects.clone(), None),
            Err(e) => (vec![], Some(TransitionError {
                kind: e.error_kind(),
                message: e.to_string(),
                retryable: e.is_retryable(),
            })),
        };

        let actual_to_state = if result.is_ok() { to_state } else { "failed" };

        // ── Append to event log (immutable, append-only) ──
        self.ctx.event_log.record(TransitionEvent {
            sequence: seq,
            timestamp,
            flow_type: self.flow_type,
            from_state: self.from_state,
            to_state: actual_to_state,
            transition: self.transition_name,
            duration,
            metadata,
            side_effects,
            error,
        });

        // ── Emit metrics ──
        self.ctx.metrics.record_transition(
            self.flow_type,
            self.from_state,
            actual_to_state,
            self.transition_name,
            duration,
            result.is_ok(),
        );

        // Emit per-side-effect metrics
        if let Ok((_, effects)) = &result {
            for effect in effects {
                self.ctx.metrics.record_side_effect(
                    self.flow_type,
                    &effect.target,
                    &effect.operation,
                    effect.duration,
                    effect.success,
                );
            }
        }

        // ── Reset state timer for the next state ──
        if result.is_ok() {
            self.ctx.enter_state();
        }

        result.map(|(value, _)| value)
    }

    /// Record a timeout event in the log (does not execute the transition).
    fn record_timeout_event(
        &mut self,
        timeout_type: &str,
        metadata: &TransitionMetadata,
        elapsed: Duration,
    ) {
        let seq = self.ctx.event_log.events.len() as u64;
        self.ctx.event_log.record(TransitionEvent {
            sequence: seq,
            timestamp: Utc::now(),
            flow_type: self.flow_type,
            from_state: self.from_state,
            to_state: "timed_out",
            transition: self.transition_name,
            duration: Duration::ZERO,  // Transition never executed
            metadata: metadata.clone(),
            side_effects: vec![],
            error: Some(TransitionError {
                kind: ErrorKind::Timeout,
                message: format!(
                    "{}: {} in state '{}' after {:?}",
                    timeout_type, self.flow_type,
                    self.from_state, elapsed,
                ),
                retryable: false,
            }),
        });
    }
}

/// Collects side effects during a transition for recording.
pub struct SideEffectCollector {
    effects: Vec<SideEffectRecord>,
}

impl SideEffectCollector {
    pub fn new() -> Self {
        Self { effects: Vec::new() }
    }

    /// Track an external call (Cognito, SES, SNS, DynamoDB).
    pub async fn track<F, Fut, T>(
        &mut self,
        effect_type: SideEffectType,
        target: &str,
        operation: &str,
        f: F,
    ) -> Result<T, AuthError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, AuthError>>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();

        self.effects.push(SideEffectRecord {
            effect_type,
            target: target.to_string(),
            operation: operation.to_string(),
            duration,
            success: result.is_ok(),
            error_code: result.as_ref().err().map(|e| e.code().to_string()),
        });

        result
    }

    pub fn finish(self) -> Vec<SideEffectRecord> {
        self.effects
    }
}
```

### Metrics Emitter

```rust
/// Emits metrics for every transition and side effect.
/// Backed by CloudWatch, Prometheus, or both.
pub struct MetricsEmitter {
    backend: Arc<dyn MetricsBackend>,
}

impl MetricsEmitter {
    /// Record a state transition with timing.
    pub fn record_transition(
        &self,
        flow_type: &str,
        from_state: &str,
        to_state: &str,
        transition: &str,
        duration: Duration,
        success: bool,
    ) {
        // Histogram: transition duration
        // Labels: flow_type, from_state, to_state, transition, success
        self.backend.histogram(
            "forgegate.identity.transition.duration",
            duration.as_secs_f64(),
            &[
                ("flow_type", flow_type),
                ("from_state", from_state),
                ("to_state", to_state),
                ("transition", transition),
                ("success", if success { "true" } else { "false" }),
            ],
        );

        // Counter: transition count
        self.backend.counter(
            "forgegate.identity.transition.count",
            1,
            &[
                ("flow_type", flow_type),
                ("from_state", from_state),
                ("to_state", to_state),
                ("success", if success { "true" } else { "false" }),
            ],
        );
    }

    /// Record a side effect (external call) with timing.
    pub fn record_side_effect(
        &self,
        flow_type: &str,
        target: &str,
        operation: &str,
        duration: Duration,
        success: bool,
    ) {
        self.backend.histogram(
            "forgegate.identity.side_effect.duration",
            duration.as_secs_f64(),
            &[
                ("flow_type", flow_type),
                ("target", target),
                ("operation", operation),
                ("success", if success { "true" } else { "false" }),
            ],
        );
    }

    /// Record total flow completion.
    pub fn record_flow_complete(
        &self,
        flow_type: &str,
        total_duration: Duration,
        success: bool,
        transition_count: usize,
    ) {
        self.backend.histogram(
            "forgegate.identity.flow.duration",
            total_duration.as_secs_f64(),
            &[
                ("flow_type", flow_type),
                ("success", if success { "true" } else { "false" }),
            ],
        );

        self.backend.histogram(
            "forgegate.identity.flow.transition_count",
            transition_count as f64,
            &[("flow_type", flow_type)],
        );
    }
}
```

### Available Metrics

| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `forgegate.identity.transition.duration` | Histogram | flow_type, from_state, to_state, transition, success | Per-transition latency (P50, P95, P99) |
| `forgegate.identity.transition.count` | Counter | flow_type, from_state, to_state, success | Transition throughput and failure rates |
| `forgegate.identity.side_effect.duration` | Histogram | flow_type, target, operation, success | External call latency (Cognito, SES, SNS) |
| `forgegate.identity.flow.duration` | Histogram | flow_type, success | Total end-to-end flow duration |
| `forgegate.identity.flow.transition_count` | Histogram | flow_type | How many steps each flow takes |
| `forgegate.identity.timeout.count` | Counter | flow_type, state, timeout_type | Timeout events (flow-level or per-state) |
| `forgegate.identity.flow.abandoned` | Counter | flow_type, last_state | Flows reaped by the FlowReaper |
| `forgegate.identity.flow.killed` | Counter | flow_type, last_state | Flows manually killed via God Mode |
| `forgegate.identity.state.dwell_time` | Histogram | flow_type, state | How long flows spend in each state |

These enable dashboards like:

- "Magic link flows take 3.2s end-to-end — 2.8s of that is SES SendEmail"
- "5% of password flows hit MFA, and those take 12s longer on average"
- "OIDC callback→token exchange is the bottleneck at P99 (800ms)"
- "Cognito InitiateAuth failure rate spiked to 2% at 14:32 UTC"

### Event Log Persistence

```rust
/// Persists the complete event log for a flow after it completes.
/// Append-only storage — logs are never modified or deleted.
pub struct EventLogStore {
    /// DynamoDB for hot storage (queryable by flow_id, project, time range).
    dynamo: DynamoClient,
    /// S3 for cold storage (archived after retention period).
    s3: S3Client,
    /// Retention policy.
    hot_retention: Duration,   // e.g., 90 days in DynamoDB
    cold_retention: Duration,  // e.g., 7 years in S3 (compliance)
}

impl EventLogStore {
    /// Called when a flow completes (success or failure).
    /// Writes the entire event log as a single immutable record.
    pub async fn persist(&self, ctx: &FlowContext, outcome: FlowOutcome) {
        let record = FlowRecord {
            flow_id: ctx.flow_id.clone(),
            project_id: ctx.project_id.clone(),
            tenant_id: ctx.tenant_id.clone(),
            started_at: ctx.started_at,
            completed_at: Utc::now(),
            total_duration: ctx.event_log.total_duration(),
            outcome,
            client_ip: ctx.client_ip,
            user_agent: ctx.user_agent.clone(),
            events: ctx.event_log.events().to_vec(),
            transition_count: ctx.event_log.events().len(),
        };

        // Write to DynamoDB (hot, queryable)
        self.dynamo.put_item(&record).await.unwrap_or_else(|e| {
            tracing::error!("Failed to persist flow event log: {e}");
        });

        // Async archive to S3 (cold, compliance)
        tokio::spawn({
            let s3 = self.s3.clone();
            let record = record.clone();
            async move {
                let key = format!(
                    "flows/{}/{}/{}.json",
                    record.project_id,
                    record.started_at.format("%Y/%m/%d"),
                    record.flow_id,
                );
                s3.put_json(&key, &record).await.ok();
            }
        });
    }
}

pub enum FlowOutcome {
    Success { user_id: UserId },
    Failed { error: ErrorKind, at_state: String },
    Abandoned { last_state: String },
    Killed { operator: UserId, reason: String, at_state: String },
}
```

### Querying the Event Log

The dashboard and API can query flow logs for debugging and audit:

```rust
/// Query interface for the event log.
impl EventLogStore {
    /// Get the complete event trace for a single flow.
    pub async fn get_flow(&self, flow_id: &FlowId) -> Option<FlowRecord> { ... }

    /// List flows for a project/tenant with filters.
    pub async fn list_flows(&self, query: FlowQuery) -> Vec<FlowSummary> { ... }

    /// Find flows that failed at a specific state.
    pub async fn find_failures(
        &self,
        project_id: &ProjectId,
        error_kind: ErrorKind,
        time_range: TimeRange,
    ) -> Vec<FlowRecord> { ... }

    /// Aggregate statistics for a flow type.
    pub async fn flow_stats(
        &self,
        project_id: &ProjectId,
        flow_type: &str,
        time_range: TimeRange,
    ) -> FlowStats { ... }
}

pub struct FlowQuery {
    pub project_id: ProjectId,
    pub tenant_id: Option<TenantId>,
    pub flow_type: Option<String>,
    pub outcome: Option<FlowOutcome>,
    pub time_range: TimeRange,
    pub limit: usize,
}

pub struct FlowStats {
    pub total_flows: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub abandoned_count: u64,
    pub avg_duration: Duration,
    pub p50_duration: Duration,
    pub p95_duration: Duration,
    pub p99_duration: Duration,
    pub avg_transition_count: f64,
    pub most_common_failure: Option<(ErrorKind, u64)>,
    pub slowest_transition: Option<(String, Duration)>,
}
```

### Dashboard: Flow Inspector

The event log powers a Flow Inspector in the dashboard — a step-by-step replay of any authentication attempt:

```
┌──────────────────────────────────────────────────────────────┐
│  Flow Inspector: flow_a1b2c3d4                                │
│  Type: magic_link │ Outcome: ✅ Success │ Total: 4.2s        │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  #0  14:32:01.000  Initiated → LinkSent              1.8s   │
│      ├── transition: request_link                             │
│      ├── metadata: principal=j***@acme.com                    │
│      └── side effects:                                        │
│          ├── Cognito InitiateAuth (CUSTOM_AUTH)      120ms ✅│
│          ├── DynamoDB PutItem (challenge code)        15ms ✅│
│          └── SES SendEmail (magic link)             1650ms ✅│
│                                                               │
│  #1  14:32:18.200  LinkSent → CodeVerified           0.3s   │
│      ├── transition: verify_code                              │
│      ├── metadata: code_age=17.2s                             │
│      └── side effects:                                        │
│          ├── DynamoDB GetItem (verify code)            8ms ✅│
│          ├── Cognito RespondToChallenge               280ms ✅│
│          └── DynamoDB DeleteItem (cleanup)             12ms ✅│
│                                                               │
│  #2  14:32:18.500  CodeVerified → Complete            0.1s   │
│      ├── transition: complete                                 │
│      ├── metadata: user_id=user_***456, tenant=acme           │
│      └── side effects:                                        │
│          └── Cognito tokens issued                    95ms ✅│
│                                                               │
│  Timeline:                                                    │
│  ├───────── 1.8s ─────────┤ 16.4s wait ├── 0.4s ──┤         │
│  #0 request_link           (user clicks)   #1 + #2            │
│                                                               │
│  Total transitions: 3 │ Side effects: 7 │ All succeeded      │
└──────────────────────────────────────────────────────────────┘
```

For a failed flow:

```
┌──────────────────────────────────────────────────────────────┐
│  Flow Inspector: flow_e5f6g7h8                                │
│  Type: password │ Outcome: ❌ Failed │ Total: 0.4s            │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  #0  14:45:02.100  Initiated → FAILED                0.4s   │
│      ├── transition: submit_credentials                       │
│      ├── metadata: principal=b***@acme.com                    │
│      ├── error: InvalidCredentials                            │
│      │          "Incorrect username or password"              │
│      │          retryable: true                               │
│      └── side effects:                                        │
│          └── Cognito InitiateAuth              380ms ❌      │
│              error_code: NotAuthorizedException               │
│                                                               │
│  ⚠ This is the 4th failed attempt from this IP in 5 minutes │
│    → authorization.denied.repeated webhook will fire at 5     │
└──────────────────────────────────────────────────────────────┘
```

For an abandoned (timed-out) flow:

```
┌──────────────────────────────────────────────────────────────┐
│  Flow Inspector: flow_t9u0v1w2                                │
│  Type: magic_link │ Outcome: ⏰ Abandoned │ Total: 15m 0.0s   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  #0  09:15:00.000  Initiated → LinkSent              2.1s   │
│      ├── transition: request_link                             │
│      ├── metadata: principal=a***@acme.com                    │
│      └── side effects:                                        │
│          ├── Cognito InitiateAuth (CUSTOM_AUTH)      105ms ✅│
│          ├── DynamoDB PutItem (challenge code)        12ms ✅│
│          └── SES SendEmail (magic link)             1980ms ✅│
│                                                               │
│  #1  09:30:00.000  LinkSent → TIMED_OUT                      │
│      ├── transition: reaper_timeout                           │
│      ├── error: Timeout                                       │
│      │          "Flow abandoned: exceeded max lifetime (900s)" │
│      │          retryable: false                              │
│      └── side effects: (none — transition never executed)     │
│                                                               │
│  Timeline:                                                    │
│  ├── 2.1s ──┤ ──── 14m 57.9s waiting ──── ┤ reaped          │
│  #0          (user never clicked the link)    #1              │
│                                                               │
│  Total transitions: 2 │ Cleanup: challenge code deleted       │
└──────────────────────────────────────────────────────────────┘
```

For a state-level timeout (MFA not entered in time):

```
┌──────────────────────────────────────────────────────────────┐
│  Flow Inspector: flow_x3y4z5a6                                │
│  Type: password │ Outcome: ⏰ State Timeout │ Total: 3m 12s   │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  #0  10:00:00.000  Initiated → Authenticated         0.5s   │
│      ├── transition: submit_credentials                       │
│      └── side effects:                                        │
│          └── Cognito InitiateAuth               480ms ✅     │
│                                                               │
│  #1  10:00:00.500  Authenticated → MfaRequired       0.1s   │
│      ├── transition: mfa_challenge_issued                     │
│      ├── metadata: mfa_method=totp                            │
│      └── side effects: (MFA prompt sent to client)            │
│                                                               │
│  #2  10:03:12.000  MfaRequired → TIMED_OUT                   │
│      ├── transition: submit_mfa (never executed)              │
│      ├── error: Timeout                                       │
│      │          "state_timeout: password in state              │
│      │          'mfa_required' after 191.5s (max: 180s)"     │
│      │          retryable: false                              │
│      └── side effects: (none)                                 │
│                                                               │
│  ℹ User authenticated successfully but did not enter          │
│    their MFA code within the 3-minute window.                 │
└──────────────────────────────────────────────────────────────┘
```

---

## Password Authentication Flow

The most common flow. Maps to Cognito's `USER_SRP_AUTH` or `USER_PASSWORD_AUTH`.

### State Diagram

```
    ┌───────────┐
    │ Initiated │
    └─────┬─────┘
          │ submit_credentials(email, password)
          ▼
    ┌───────────────┐
    │ Authenticated  │──────────────────────┐
    └───────┬───────┘                       │
            │                               │
     ┌──────┴──────┐                        │
     │ MFA enabled? │                       │ MFA not required
     └──────┬──────┘                        │
            │ yes                           │
            ▼                               │
    ┌───────────────┐                       │
    │ MfaRequired   │                       │
    └───────┬───────┘                       │
            │ submit_mfa(code)              │
            ▼                               ▼
    ┌───────────────┐               ┌──────────────┐
    │ MfaVerified   │──────────────►│  Complete     │
    └───────────────┘               └──────────────┘
```

### Implementation

```rust
// ── States (zero-sized types, exist only at compile time) ──

pub mod password {
    use super::*;

    pub struct Initiated;
    pub struct Authenticated {
        pub user_id: UserId,
        pub session: CognitoSession,
    }
    pub struct MfaRequired {
        pub user_id: UserId,
        pub session: CognitoSession,
        pub mfa_method: MfaMethod,
    }
    pub struct MfaVerified {
        pub user_id: UserId,
    }

    impl AuthState for Initiated {
        fn state_name() -> &'static str { "initiated" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(60))  // 1 min to submit credentials
        }
    }
    impl AuthState for Authenticated {
        fn state_name() -> &'static str { "authenticated" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(5))   // Transient — complete immediately
        }
    }
    impl AuthState for MfaRequired {
        fn state_name() -> &'static str { "mfa_required" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(180)) // 3 min to enter MFA code
        }
    }
    impl AuthState for MfaVerified {
        fn state_name() -> &'static str { "mfa_verified" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(5))   // Transient — complete immediately
        }
    }
}

/// The password flow, parameterized by its current state.
/// You can only call methods valid for the current state.
pub struct PasswordFlow<S: AuthState> {
    state: S,
    ctx: FlowContext,
    cognito: CognitoAdapter,
}

// ── Transitions ──

impl PasswordFlow<password::Initiated> {
    /// Create a new password authentication flow.
    pub fn new(ctx: FlowContext, cognito: CognitoAdapter) -> Self {
        Self {
            state: password::Initiated,
            ctx,
            cognito,
        }
    }

    /// Submit credentials. Consumes Initiated, produces
    /// Authenticated or MfaRequired.
    /// Every transition is recorded in the append-only event log.
    pub async fn submit_credentials(
        mut self,
        email: &Email,
        password: &SecretString,
    ) -> Result<PasswordAfterCredentials, AuthError> {
        let recorder = TransitionRecorder::new(
            &mut self.ctx,
            "password",
            password::Initiated::state_name(),
            "submit_credentials",
        );

        recorder.execute(
            password::Authenticated::state_name(),
            TransitionMetadata {
                principal_hint: Some(email.redacted()),
                auth_method: Some("password".into()),
                ..Default::default()
            },
            |mut collector| async move {
                // Call Cognito — tracked as a side effect
                let result = collector.track(
                    SideEffectType::CognitoApiCall,
                    "Cognito",
                    "InitiateAuth",
                    || self.cognito.initiate_auth(
                        &self.ctx,
                        AuthFlow::UserPasswordAuth,
                        &[
                            ("USERNAME", email.as_str()),
                            ("PASSWORD", password.expose_secret()),
                        ],
                    ),
                ).await?;

                let effects = collector.finish();

                match result {
                    CognitoAuthResult::Success(tokens) => {
                        Ok((PasswordAfterCredentials::Authenticated(
                            PasswordFlow {
                                state: password::Authenticated {
                                    user_id: UserId::from_token(&tokens),
                                    session: result.session,
                                },
                                ctx: self.ctx,
                                cognito: self.cognito,
                            }
                        ), effects))
                    }
                    CognitoAuthResult::MfaChallenge { session, mfa_method } => {
                        Ok((PasswordAfterCredentials::MfaRequired(
                            PasswordFlow {
                                state: password::MfaRequired {
                                    user_id: UserId::from_session(&session),
                                    session,
                                    mfa_method,
                                },
                                ctx: self.ctx,
                                cognito: self.cognito,
                            }
                        ), effects))
                    }
                    CognitoAuthResult::Failure(e) => Err(e.into()),
                }
            },
        ).await
    }
}

/// Branching result — the compiler forces callers to handle both cases.
pub enum PasswordAfterCredentials {
    Authenticated(PasswordFlow<password::Authenticated>),
    MfaRequired(PasswordFlow<password::MfaRequired>),
}

impl PasswordFlow<password::Authenticated> {
    /// Complete the flow (no MFA needed).
    pub async fn complete(self) -> Result<AuthSuccess, AuthError> {
        let tokens = self.cognito.get_tokens(&self.state.session).await?;
        Ok(AuthSuccess {
            user_id: self.state.user_id,
            tenant_id: self.ctx.tenant_id.unwrap_or_default(),
            tokens,
            session: Session::new(&self.ctx),
        })
    }
}

impl PasswordFlow<password::MfaRequired> {
    /// Which MFA method was requested.
    pub fn mfa_method(&self) -> &MfaMethod {
        &self.state.mfa_method
    }

    /// Submit MFA code. Consumes MfaRequired, produces MfaVerified.
    pub async fn submit_mfa(
        self,
        code: &MfaCode,
    ) -> Result<PasswordFlow<password::MfaVerified>, AuthError> {
        self.cognito.respond_to_challenge(
            &self.state.session,
            ChallengeResponse::MfaCode(code),
        ).await?;

        Ok(PasswordFlow {
            state: password::MfaVerified {
                user_id: self.state.user_id,
            },
            ctx: self.ctx,
            cognito: self.cognito,
        })
    }
}

impl PasswordFlow<password::MfaVerified> {
    /// Complete the flow after MFA.
    pub async fn complete(self) -> Result<AuthSuccess, AuthError> {
        // Token generation happens here
        Ok(AuthSuccess {
            user_id: self.state.user_id,
            tenant_id: self.ctx.tenant_id.unwrap_or_default(),
            tokens: self.cognito.finalize_tokens().await?,
            session: Session::new(&self.ctx),
        })
    }
}
```

**Key property:** You literally cannot call `submit_mfa` on an `Initiated` flow or `submit_credentials` on an `MfaRequired` flow. The compiler rejects it. There is no runtime check — the invalid code does not compile.

---

## Magic Link Flow

Maps to Cognito's `CUSTOM_AUTH` with a challenge-response cycle managed by ForgeGate's Lambda triggers and DynamoDB.

### State Diagram

```
    ┌───────────┐
    │ Initiated │
    └─────┬─────┘
          │ request_link(email)
          ▼
    ┌────────────────┐
    │ LinkSent       │    (email delivered, code in DynamoDB)
    └───────┬────────┘
            │ verify_code(code)
            ▼
    ┌───────────────────┐
    │ CodeVerified      │
    └───────┬───────────┘
            │ MFA check (same as password flow)
            ▼
    ┌───────────────┐     ┌──────────────┐
    │ MfaRequired   │────►│  Complete    │
    └───────────────┘     └──────────────┘
```

### Implementation

```rust
pub mod magic_link {
    use super::*;

    pub struct Initiated;
    pub struct LinkSent {
        pub email: Email,
        pub code_hash: String,
        pub expires_at: Instant,
        pub cognito_session: CognitoSession,
    }
    pub struct CodeVerified {
        pub user_id: UserId,
        pub cognito_session: CognitoSession,
    }
    pub struct MfaRequired {
        pub user_id: UserId,
        pub cognito_session: CognitoSession,
        pub mfa_method: MfaMethod,
    }

    impl AuthState for Initiated {
        fn state_name() -> &'static str { "initiated" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(30))   // 30s to request the link
        }
    }
    impl AuthState for LinkSent {
        fn state_name() -> &'static str { "link_sent" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(900))  // 15 min to click the link
        }
    }
    impl AuthState for CodeVerified {
        fn state_name() -> &'static str { "code_verified" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(5))    // Transient
        }
    }
    impl AuthState for MfaRequired {
        fn state_name() -> &'static str { "mfa_required" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(180))  // 3 min for MFA
        }
    }
}

pub struct MagicLinkFlow<S: AuthState> {
    state: S,
    ctx: FlowContext,
    cognito: CognitoAdapter,
    challenges: ChallengeStore,  // DynamoDB
    mailer: EmailSender,         // SES
    config: MagicLinkConfig,
}

impl MagicLinkFlow<magic_link::Initiated> {
    pub async fn request_link(
        self,
        email: &Email,
    ) -> Result<MagicLinkFlow<magic_link::LinkSent>, AuthError> {
        // 1. Initiate CUSTOM_AUTH with Cognito
        let session = self.cognito.initiate_custom_auth(
            &self.ctx,
            email,
        ).await?;

        // 2. Generate secure code
        let code = ChallengeCode::generate();
        let code_hash = code.hash();

        // 3. Store in DynamoDB with TTL
        self.challenges.store(
            &self.ctx.flow_id,
            &code_hash,
            self.config.expiry,
        ).await?;

        // 4. Build magic link URL
        let link = format!(
            "https://{}/auth/verify?flow={}&code={}",
            self.config.app_domain,
            self.ctx.flow_id,
            code.as_str(),
        );

        // 5. Send email via SES
        self.mailer.send(
            email,
            &self.config.template,
            &TemplateVars {
                app_name: &self.config.app_name,
                link: &link,
                code: code.as_str(),
                expiry: &self.config.expiry.as_minutes().to_string(),
                email: email.as_str(),
            },
        ).await?;

        Ok(MagicLinkFlow {
            state: magic_link::LinkSent {
                email: email.clone(),
                code_hash,
                expires_at: Instant::now() + self.config.expiry,
                cognito_session: session,
            },
            ctx: self.ctx,
            cognito: self.cognito,
            challenges: self.challenges,
            mailer: self.mailer,
            config: self.config,
        })
    }
}

impl MagicLinkFlow<magic_link::LinkSent> {
    /// How much time remains before the code expires.
    pub fn time_remaining(&self) -> Duration {
        self.state.expires_at.saturating_duration_since(Instant::now())
    }

    /// Verify the code from the magic link.
    pub async fn verify_code(
        self,
        code: &ChallengeCode,
    ) -> Result<MagicLinkAfterVerify, AuthError> {
        // Check expiry
        if Instant::now() > self.state.expires_at {
            // Clean up
            self.challenges.delete(&self.ctx.flow_id).await?;
            return Err(AuthError::CodeExpired);
        }

        // Verify hash
        if !code.verify_against(&self.state.code_hash) {
            return Err(AuthError::InvalidCode);
        }

        // Respond to Cognito CUSTOM_CHALLENGE
        let result = self.cognito.respond_to_custom_challenge(
            &self.state.cognito_session,
            code.as_str(),
        ).await?;

        // Clean up challenge
        self.challenges.delete(&self.ctx.flow_id).await?;

        match result {
            CognitoAuthResult::Success(tokens) => {
                Ok(MagicLinkAfterVerify::Verified(MagicLinkFlow {
                    state: magic_link::CodeVerified {
                        user_id: UserId::from_token(&tokens),
                        cognito_session: self.state.cognito_session,
                    },
                    ctx: self.ctx,
                    cognito: self.cognito,
                    challenges: self.challenges,
                    mailer: self.mailer,
                    config: self.config,
                }))
            }
            CognitoAuthResult::MfaChallenge { session, mfa_method } => {
                Ok(MagicLinkAfterVerify::MfaRequired(MagicLinkFlow {
                    state: magic_link::MfaRequired {
                        user_id: UserId::from_session(&session),
                        cognito_session: session,
                        mfa_method,
                    },
                    ctx: self.ctx,
                    cognito: self.cognito,
                    challenges: self.challenges,
                    mailer: self.mailer,
                    config: self.config,
                }))
            }
            CognitoAuthResult::Failure(e) => Err(e.into()),
        }
    }
}

pub enum MagicLinkAfterVerify {
    Verified(MagicLinkFlow<magic_link::CodeVerified>),
    MfaRequired(MagicLinkFlow<magic_link::MfaRequired>),
}
```

---

## OIDC / Social Login Flow

Maps to Cognito's hosted UI OAuth2 flow with external identity providers.

### State Diagram

```
    ┌───────────┐
    │ Initiated │
    └─────┬─────┘
          │ start(provider)
          ▼
    ┌─────────────────┐
    │ RedirectPending  │    → user redirected to IdP
    └───────┬─────────┘
            │ handle_callback(code, state)
            ▼
    ┌───────────────────┐
    │ CallbackReceived  │    → exchange code for tokens
    └───────┬───────────┘
            │
     ┌──────┴──────┐
     │ New user?    │
     └──────┬──────┘
            │
    ┌───────┴────────┐
    │                │
    ▼                ▼
  ┌──────────┐   ┌──────────────┐
  │ NewUser  │   │ ExistingUser │
  │ (provision)│ │              │
  └────┬─────┘   └──────┬───────┘
       │                │
       └────────┬───────┘
                ▼
        ┌──────────────┐
        │  Complete    │
        └──────────────┘
```

### Implementation

```rust
pub mod oidc {
    use super::*;

    pub struct Initiated;
    pub struct RedirectPending {
        pub provider: ProviderName,
        pub state_param: OAuthState,
        pub nonce: Nonce,
        pub pkce_verifier: PkceVerifier,
        pub redirect_url: Url,
    }
    pub struct CallbackReceived {
        pub provider: ProviderName,
        pub id_token_claims: Claims,
        pub cognito_tokens: Option<TokenSet>,
    }
    pub struct NewUser {
        pub provider: ProviderName,
        pub external_id: String,
        pub email: Email,
        pub claims: Claims,
    }
    pub struct ExistingUser {
        pub user_id: UserId,
    }

    impl AuthState for Initiated {
        fn state_name() -> &'static str { "initiated" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(30))   // 30s to start redirect
        }
    }
    impl AuthState for RedirectPending {
        fn state_name() -> &'static str { "redirect_pending" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(600))  // 10 min to complete IdP login
        }
    }
    impl AuthState for CallbackReceived {
        fn state_name() -> &'static str { "callback_received" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(10))   // Transient — processing
        }
    }
    impl AuthState for NewUser {
        fn state_name() -> &'static str { "new_user" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(10))   // Transient — provisioning
        }
    }
    impl AuthState for ExistingUser {
        fn state_name() -> &'static str { "existing_user" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(5))    // Transient — token issuance
        }
    }
}

impl OidcFlow<oidc::Initiated> {
    /// Start the OIDC flow — returns the URL to redirect the user to.
    pub async fn start(
        self,
        provider: &ProviderName,
    ) -> Result<OidcFlow<oidc::RedirectPending>, AuthError> {
        let provider_config = self.config.get_provider(provider)?;

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceChallenge::generate();

        // Generate state and nonce for CSRF/replay protection
        let state_param = OAuthState::generate();
        let nonce = Nonce::generate();

        // Store state → flow mapping for callback
        self.state_store.store(
            &state_param,
            &StateData {
                flow_id: self.ctx.flow_id.clone(),
                provider: provider.clone(),
                nonce: nonce.clone(),
                pkce_verifier: pkce_verifier.clone(),
            },
            Duration::from_secs(600),  // 10 min expiry
        ).await?;

        // Build authorization URL
        let redirect_url = provider_config.build_auth_url(
            &state_param,
            &nonce,
            &pkce_challenge,
        );

        Ok(OidcFlow {
            state: oidc::RedirectPending {
                provider: provider.clone(),
                state_param,
                nonce,
                pkce_verifier,
                redirect_url,
            },
            ctx: self.ctx,
            cognito: self.cognito,
            config: self.config,
            state_store: self.state_store,
        })
    }
}

impl OidcFlow<oidc::RedirectPending> {
    /// The URL to redirect the user to.
    pub fn redirect_url(&self) -> &Url {
        &self.state.redirect_url
    }

    /// Handle the callback from the identity provider.
    pub async fn handle_callback(
        self,
        code: &AuthorizationCode,
        state: &OAuthState,
    ) -> Result<OidcAfterCallback, AuthError> {
        // Verify state matches (CSRF protection)
        if state != &self.state.state_param {
            return Err(AuthError::InvalidOAuthState);
        }

        // Exchange code for tokens at the IdP
        let idp_tokens = self.cognito.exchange_code(
            &self.state.provider,
            code,
            &self.state.pkce_verifier,
        ).await?;

        // Verify ID token signature and nonce
        let claims = idp_tokens.verify_id_token(
            &self.state.nonce,
        )?;

        // Check if user exists in Cognito
        let existing = self.cognito.find_user_by_provider(
            &self.state.provider,
            &claims.sub,
        ).await?;

        match existing {
            Some(user) => Ok(OidcAfterCallback::ExistingUser(
                OidcFlow {
                    state: oidc::ExistingUser { user_id: user.id },
                    ..self.transfer()
                }
            )),
            None => Ok(OidcAfterCallback::NewUser(
                OidcFlow {
                    state: oidc::NewUser {
                        provider: self.state.provider,
                        external_id: claims.sub.clone(),
                        email: claims.email.clone(),
                        claims,
                    },
                    ..self.transfer()
                }
            )),
        }
    }
}

pub enum OidcAfterCallback {
    ExistingUser(OidcFlow<oidc::ExistingUser>),
    NewUser(OidcFlow<oidc::NewUser>),
}

impl OidcFlow<oidc::NewUser> {
    /// Provision the new user in Cognito and ForgeGate.
    pub async fn provision(
        self,
        tenant_id: &TenantId,
        default_role: &RoleName,
    ) -> Result<AuthSuccess, AuthError> {
        // Create user in Cognito (federated, auto-confirmed)
        let user_id = self.cognito.create_federated_user(
            &self.state.provider,
            &self.state.external_id,
            &self.state.email,
            &self.state.claims,
        ).await?;

        // Assign to tenant and role in ForgeGate
        self.forgegate.assign_user(
            &user_id, tenant_id, default_role,
        ).await?;

        // Generate tokens
        let tokens = self.cognito.tokens_for_user(&user_id).await?;

        Ok(AuthSuccess {
            user_id,
            tenant_id: tenant_id.clone(),
            tokens,
            session: Session::new(&self.ctx),
        })
    }
}
```

---

## Password Reset Flow

```
    ┌───────────┐
    │ Initiated │
    └─────┬─────┘
          │ request_reset(email)
          ▼
    ┌────────────────┐
    │ CodeSent       │    (Cognito sends reset code)
    └───────┬────────┘
            │ confirm_reset(code, new_password)
            ▼
    ┌───────────────────┐
    │ PasswordChanged   │
    └───────────────────┘
```

```rust
pub mod password_reset {
    pub struct Initiated;
    pub struct CodeSent {
        pub email: Email,
        pub expires_at: Instant,
    }
    pub struct PasswordChanged {
        pub user_id: UserId,
    }

    impl AuthState for Initiated {}
    impl AuthState for CodeSent {
        fn state_name() -> &'static str { "code_sent" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(3600)) // 1 hour to use reset code
        }
    }
    impl AuthState for PasswordChanged {
        fn state_name() -> &'static str { "password_changed" }
        fn state_timeout() -> Option<Duration> { None } // Terminal
    }
}

impl PasswordResetFlow<password_reset::Initiated> {
    pub async fn request_reset(
        self,
        email: &Email,
    ) -> Result<PasswordResetFlow<password_reset::CodeSent>, AuthError> {
        // Always returns success (don't reveal if email exists)
        self.cognito.forgot_password(email).await.ok();

        Ok(PasswordResetFlow {
            state: password_reset::CodeSent {
                email: email.clone(),
                expires_at: Instant::now() + Duration::from_secs(3600),
            },
            ctx: self.ctx,
            cognito: self.cognito,
        })
    }
}

impl PasswordResetFlow<password_reset::CodeSent> {
    pub async fn confirm_reset(
        self,
        code: &ResetCode,
        new_password: &SecretString,
    ) -> Result<PasswordResetFlow<password_reset::PasswordChanged>, AuthError> {
        // Validate password against policy before hitting Cognito
        self.password_policy.validate(new_password)?;

        self.cognito.confirm_forgot_password(
            &self.state.email,
            code,
            new_password,
        ).await?;

        Ok(PasswordResetFlow {
            state: password_reset::PasswordChanged {
                user_id: self.cognito.get_user_id(&self.state.email).await?,
            },
            ctx: self.ctx,
            cognito: self.cognito,
        })
    }
}
```

---

## Sign-Up Flow

```
    ┌───────────┐
    │ Initiated │
    └─────┬─────┘
          │ register(email, password, attributes)
          ▼
    ┌────────────────────┐
    │ PendingVerification│    (confirmation code sent)
    └───────┬────────────┘
            │ verify(code)
            ▼
    ┌───────────────┐
    │ Verified      │
    └───────┬───────┘
            │ assign_tenant_and_role
            ▼
    ┌──────────────┐
    │ Provisioned  │
    └──────────────┘
```

```rust
pub mod signup {
    pub struct Initiated;
    pub struct PendingVerification {
        pub user_id: UserId,
        pub email: Email,
    }
    pub struct Verified {
        pub user_id: UserId,
        pub email: Email,
    }
    pub struct Provisioned {
        pub user_id: UserId,
        pub tenant_id: TenantId,
        pub roles: Vec<RoleName>,
    }

    impl AuthState for Initiated {}
    impl AuthState for PendingVerification {
        fn state_name() -> &'static str { "pending_verification" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(3600)) // 1 hour to verify email
        }
    }
    impl AuthState for Verified {
        fn state_name() -> &'static str { "verified" }
        fn state_timeout() -> Option<Duration> {
            Some(Duration::from_secs(10))   // Transient — provisioning
        }
    }
    impl AuthState for Provisioned {
        fn state_name() -> &'static str { "provisioned" }
        fn state_timeout() -> Option<Duration> { None } // Terminal
    }
}
```

---

## Flow Orchestrator

The orchestrator is the API-layer entry point. It receives HTTP requests, determines which flow and state to use, and drives the state machine forward.

```rust
pub struct FlowOrchestrator {
    cognito: CognitoAdapter,
    challenges: ChallengeStore,
    mailer: EmailSender,
    sms: SmsSender,
    config: AuthConfig,
    flow_store: FlowStore,        // persists in-progress flows
    event_log_store: EventLogStore, // persists completed flow event logs
    metrics: MetricsEmitter,
}

impl FlowOrchestrator {
    /// Entry point: start a new authentication.
    pub async fn initiate(
        &self,
        method: AuthMethod,
        ctx: FlowContext,
    ) -> Result<FlowResponse, AuthError> {
        match method {
            AuthMethod::Password { email, password } => {
                let flow = PasswordFlow::new(ctx, self.cognito.clone());
                match flow.submit_credentials(&email, &password).await? {
                    PasswordAfterCredentials::Authenticated(flow) => {
                        let success = flow.complete().await?;
                        Ok(FlowResponse::Success(success))
                    }
                    PasswordAfterCredentials::MfaRequired(flow) => {
                        // Persist the flow state for the next request
                        let flow_id = flow.ctx.flow_id.clone();
                        self.flow_store.save_mfa_pending(
                            &flow_id, &flow,
                        ).await?;
                        Ok(FlowResponse::MfaChallenge {
                            flow_id,
                            method: flow.mfa_method().clone(),
                        })
                    }
                }
            }

            AuthMethod::MagicLink { email } => {
                let flow = MagicLinkFlow::new(
                    ctx, self.cognito.clone(),
                    self.challenges.clone(),
                    self.mailer.clone(),
                    self.config.magic_link.clone(),
                );
                let flow = flow.request_link(&email).await?;
                let flow_id = flow.ctx.flow_id.clone();
                self.flow_store.save_link_sent(&flow_id, &flow).await?;
                Ok(FlowResponse::CodeSent { flow_id })
            }

            AuthMethod::Oidc { provider } => {
                let flow = OidcFlow::new(
                    ctx, self.cognito.clone(), self.config.clone(),
                );
                let flow = flow.start(&provider).await?;
                let redirect_url = flow.redirect_url().clone();
                let flow_id = flow.ctx.flow_id.clone();
                self.flow_store.save_redirect_pending(
                    &flow_id, &flow,
                ).await?;
                Ok(FlowResponse::Redirect { flow_id, redirect_url })
            }

            AuthMethod::SmsCode { phone } => {
                let flow = SmsCodeFlow::new(
                    ctx, self.cognito.clone(),
                    self.challenges.clone(),
                    self.sms.clone(),
                    self.config.sms_code.clone(),
                );
                let flow = flow.request_code(&phone).await?;
                let flow_id = flow.ctx.flow_id.clone();
                self.flow_store.save_code_sent(&flow_id, &flow).await?;
                Ok(FlowResponse::CodeSent { flow_id })
            }
        }
    }

    /// Continue a flow that's waiting for user input.
    pub async fn continue_flow(
        &self,
        flow_id: &FlowId,
        input: FlowInput,
    ) -> Result<FlowResponse, AuthError> {
        let saved = self.flow_store.load(flow_id).await?;

        match (saved, input) {
            // Magic link: user clicked the link
            (SavedFlow::MagicLinkSent(flow), FlowInput::VerifyCode(code)) => {
                match flow.verify_code(&code).await? {
                    MagicLinkAfterVerify::Verified(flow) => {
                        let success = flow.complete().await?;
                        self.flow_store.delete(flow_id).await?;
                        Ok(FlowResponse::Success(success))
                    }
                    MagicLinkAfterVerify::MfaRequired(flow) => {
                        self.flow_store.save_mfa_pending(
                            flow_id, &flow,
                        ).await?;
                        Ok(FlowResponse::MfaChallenge {
                            flow_id: flow_id.clone(),
                            method: flow.mfa_method().clone(),
                        })
                    }
                }
            }

            // MFA challenge response (from any flow)
            (SavedFlow::MfaPending(flow), FlowInput::MfaCode(code)) => {
                let flow = flow.submit_mfa(&code).await?;
                let success = flow.complete().await?;
                self.flow_store.delete(flow_id).await?;
                Ok(FlowResponse::Success(success))
            }

            // OIDC callback
            (SavedFlow::OidcPending(flow), FlowInput::OidcCallback { code, state }) => {
                match flow.handle_callback(&code, &state).await? {
                    OidcAfterCallback::ExistingUser(flow) => {
                        let success = flow.complete().await?;
                        self.flow_store.delete(flow_id).await?;
                        Ok(FlowResponse::Success(success))
                    }
                    OidcAfterCallback::NewUser(flow) => {
                        let success = flow.provision(
                            &self.config.default_tenant,
                            &self.config.default_role,
                        ).await?;
                        self.flow_store.delete(flow_id).await?;
                        Ok(FlowResponse::Success(success))
                    }
                }
            }

            _ => Err(AuthError::InvalidFlowState),
        }
    }
}

/// What the API returns to the client.
pub enum FlowResponse {
    Success(AuthSuccess),
    MfaChallenge { flow_id: FlowId, method: MfaMethod },
    CodeSent { flow_id: FlowId },
    Redirect { flow_id: FlowId, redirect_url: Url },
}

impl FlowOrchestrator {
    /// Wraps every successful flow completion:
    /// persists the event log and emits flow-level metrics.
    async fn complete_flow(
        &self,
        ctx: &FlowContext,
        success: &AuthSuccess,
    ) {
        // Emit flow-level metrics
        self.metrics.record_flow_complete(
            ctx.event_log.events().first()
                .map(|e| e.flow_type).unwrap_or("unknown"),
            ctx.event_log.total_duration(),
            true,
            ctx.event_log.events().len(),
        );

        // Persist the complete event log (append-only, immutable)
        self.event_log_store.persist(
            ctx,
            FlowOutcome::Success { user_id: success.user_id.clone() },
        ).await;
    }

    /// Wraps every flow failure: persists the event log with error context.
    async fn fail_flow(
        &self,
        ctx: &FlowContext,
        error: &AuthError,
        at_state: &str,
    ) {
        self.metrics.record_flow_complete(
            ctx.event_log.events().first()
                .map(|e| e.flow_type).unwrap_or("unknown"),
            ctx.event_log.total_duration(),
            false,
            ctx.event_log.events().len(),
        );

        self.event_log_store.persist(
            ctx,
            FlowOutcome::Failed {
                error: error.error_kind(),
                at_state: at_state.to_string(),
            },
        ).await;
    }
}
```

---

## Flow Reaper: Cleaning Up Abandoned Flows

Flows that are waiting for user input (magic link click, MFA code entry, OIDC callback) are persisted in the flow store. If the user never completes the flow, it must be reaped. The FlowReaper runs on a periodic schedule and kills expired flows.

```rust
/// Periodically scans for abandoned flows and terminates them.
/// Runs as a background task in the control plane.
pub struct FlowReaper {
    flow_store: FlowStore,
    event_log_store: EventLogStore,
    metrics: MetricsEmitter,
    scan_interval: Duration,  // e.g., every 60 seconds
}

impl FlowReaper {
    /// Run the reaper loop. Typically spawned as a tokio task.
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(self.scan_interval);

        loop {
            interval.tick().await;
            if let Err(e) = self.reap_expired_flows().await {
                tracing::error!("Flow reaper error: {e}");
            }
        }
    }

    async fn reap_expired_flows(&self) -> Result<(), ReaperError> {
        // Scan for flows that have exceeded their flow-level timeout
        let expired = self.flow_store.scan_expired().await?;

        for flow in expired {
            tracing::info!(
                flow_id = %flow.flow_id,
                flow_type = %flow.flow_type,
                last_state = %flow.current_state,
                age = ?flow.started_at.elapsed(),
                "Reaping abandoned flow"
            );

            // Record the abandonment in the event log
            let mut ctx = flow.context;
            ctx.event_log.record(TransitionEvent {
                sequence: ctx.event_log.events().len() as u64,
                timestamp: Utc::now(),
                flow_type: flow.flow_type,
                from_state: flow.current_state,
                to_state: "abandoned",
                transition: "reaper_timeout",
                duration: Duration::ZERO,
                metadata: TransitionMetadata::default(),
                side_effects: vec![],
                error: Some(TransitionError {
                    kind: ErrorKind::Timeout,
                    message: format!(
                        "Flow abandoned: exceeded max lifetime ({:?})",
                        ctx.timeouts.flow_max_lifetime,
                    ),
                    retryable: false,
                }),
            });

            // Persist the event log with abandoned outcome
            self.event_log_store.persist(
                &ctx,
                FlowOutcome::Abandoned {
                    last_state: flow.current_state.to_string(),
                },
            ).await;

            // Clean up any side-effect resources
            // (e.g., DynamoDB challenge codes for magic links)
            self.cleanup_flow_resources(&flow).await?;

            // Remove from flow store
            self.flow_store.delete(&flow.flow_id).await?;

            // Metrics
            self.metrics.counter(
                "forgegate.identity.flow.abandoned",
                1,
                &[
                    ("flow_type", flow.flow_type),
                    ("last_state", flow.current_state),
                ],
            );
        }

        Ok(())
    }

    async fn cleanup_flow_resources(
        &self,
        flow: &PersistedFlow,
    ) -> Result<(), ReaperError> {
        match flow.flow_type {
            "magic_link" => {
                // Delete unused challenge code from DynamoDB
                self.challenges.delete(&flow.flow_id).await.ok();
            }
            "oidc" => {
                // Delete OAuth state from state store
                self.state_store.delete(&flow.oauth_state).await.ok();
            }
            _ => {}
        }
        Ok(())
    }
}
```

### Default Timeouts Reference

| Flow Type | Flow Max Lifetime | Per-State Timeouts |
|-----------|------------------|--------------------|
| Password | 5 min | Initiated: 60s, Authenticated: 5s, MfaRequired: 3 min, MfaVerified: 5s |
| Magic Link | 15 min | Initiated: 30s, LinkSent: 15 min, CodeVerified: 5s, MfaRequired: 3 min |
| SMS Code | 10 min | Initiated: 30s, CodeSent: 5 min, CodeVerified: 5s, MfaRequired: 3 min |
| OIDC / Social | 10 min | Initiated: 30s, RedirectPending: 10 min, Callback: 10s, NewUser: 10s, ExistingUser: 5s |
| Password Reset | 1 hour | Initiated: 30s, CodeSent: 1 hour, PasswordChanged: terminal |
| Sign-Up | 1 hour | Initiated: 30s, PendingVerification: 1 hour, Verified: 10s, Provisioned: terminal |

All timeouts are configurable per-project through the dashboard or `authentication.timeouts` config section. The flow-level timeout is always enforced even if per-state timeouts are disabled.

### Manual Flow Operations (God Mode)

The God Mode dashboard provides operators with the ability to intervene in live flows. These operations are backed by the flow store and fully event-logged.

```rust
/// Manual interventions on live flows, invoked from God Mode.
/// Every action is audit-logged with the operator's identity.
pub struct FlowOperations {
    flow_store: FlowStore,
    event_log_store: EventLogStore,
    metrics: MetricsEmitter,
    webhook_dispatcher: WebhookDispatcher,
}

impl FlowOperations {
    /// Manually terminate a live flow. The user sees "session expired."
    /// Records a manual_kill event with full operator attribution.
    pub async fn kill_flow(
        &self,
        flow_id: &FlowId,
        operator: &OperatorIdentity,
        reason: &str,
    ) -> Result<(), FlowError> {
        let mut flow = self.flow_store.load(flow_id).await?;

        // Record the kill in the flow's event log
        flow.context.event_log.record(TransitionEvent {
            sequence: flow.context.event_log.events().len() as u64,
            timestamp: Utc::now(),
            flow_type: flow.flow_type,
            from_state: flow.current_state,
            to_state: "killed",
            transition: "manual_kill",
            duration: Duration::ZERO,
            metadata: TransitionMetadata {
                principal_hint: Some(format!(
                    "operator:{}",
                    operator.user_id
                )),
                ..Default::default()
            },
            side_effects: vec![],
            error: Some(TransitionError {
                kind: ErrorKind::ManualKill,
                message: format!(
                    "Killed by operator {} — reason: {}",
                    operator.user_id, reason,
                ),
                retryable: false,
            }),
        });

        // Persist the event log
        self.event_log_store.persist(
            &flow.context,
            FlowOutcome::Killed {
                operator: operator.user_id.clone(),
                reason: reason.to_string(),
                at_state: flow.current_state.to_string(),
            },
        ).await;

        // Clean up resources and remove from store
        self.cleanup_flow_resources(&flow).await?;
        self.flow_store.delete(flow_id).await?;

        // Emit webhook event
        self.webhook_dispatcher.dispatch(Event {
            event_type: "flow.killed",
            entity_type: "flow",
            entity_id: flow_id.to_string(),
            actor: Actor::Operator(operator.clone()),
            data: json!({
                "flow_type": flow.flow_type,
                "last_state": flow.current_state,
                "reason": reason,
                "flow_age_seconds": flow.context.started_at.elapsed().as_secs(),
            }),
        }).await;

        // Metrics
        self.metrics.counter(
            "forgegate.identity.flow.killed",
            1,
            &[
                ("flow_type", flow.flow_type),
                ("last_state", flow.current_state),
            ],
        );

        Ok(())
    }

    /// Extend the timeout of a live flow.
    /// Useful when support is on a call with a user struggling with MFA.
    pub async fn extend_timeout(
        &self,
        flow_id: &FlowId,
        operator: &OperatorIdentity,
        additional: Duration,
        extend_flow: bool,
        extend_state: bool,
    ) -> Result<TimeoutExtension, FlowError> {
        let mut flow = self.flow_store.load_mut(flow_id).await?;

        let old_flow_expiry = flow.context.started_at
            + flow.context.timeouts.flow_max_lifetime;
        let old_state_expiry = flow.context.current_state_entered_at
            + flow.context.timeouts.effective_state_timeout_by_name(
                flow.current_state
            ).unwrap_or(Duration::MAX);

        if extend_flow {
            flow.context.timeouts.flow_max_lifetime += additional;
        }
        if extend_state {
            flow.context.timeouts.state_overrides.insert(
                flow.current_state,
                flow.context.timeouts
                    .effective_state_timeout_by_name(flow.current_state)
                    .unwrap_or(Duration::from_secs(300))
                    + additional,
            );
        }

        // Record the extension in the event log
        flow.context.event_log.record(TransitionEvent {
            sequence: flow.context.event_log.events().len() as u64,
            timestamp: Utc::now(),
            flow_type: flow.flow_type,
            from_state: flow.current_state,
            to_state: flow.current_state,  // Same state, just extended
            transition: "timeout_extended",
            duration: Duration::ZERO,
            metadata: TransitionMetadata {
                principal_hint: Some(format!(
                    "operator:{}",
                    operator.user_id
                )),
                ..Default::default()
            },
            side_effects: vec![],
            error: None,
        });

        // Save updated flow back to store
        self.flow_store.save(&flow).await?;

        // Emit webhook
        self.webhook_dispatcher.dispatch(Event {
            event_type: "flow.timeout_extended",
            entity_type: "flow",
            entity_id: flow_id.to_string(),
            actor: Actor::Operator(operator.clone()),
            data: json!({
                "flow_type": flow.flow_type,
                "current_state": flow.current_state,
                "additional_seconds": additional.as_secs(),
                "extend_flow": extend_flow,
                "extend_state": extend_state,
            }),
        }).await;

        let new_flow_expiry = flow.context.started_at
            + flow.context.timeouts.flow_max_lifetime;
        let new_state_expiry = flow.context.current_state_entered_at
            + flow.context.timeouts.effective_state_timeout_by_name(
                flow.current_state
            ).unwrap_or(Duration::MAX);

        Ok(TimeoutExtension {
            new_flow_expiry,
            new_state_expiry,
        })
    }

    /// List all in-flight flows with filtering.
    /// Backs the God Mode live dashboard.
    pub async fn list_active_flows(
        &self,
        filter: ActiveFlowFilter,
    ) -> Result<ActiveFlowSnapshot, FlowError> {
        let flows = self.flow_store.scan_active(&filter).await?;

        // Compute per-flow health status based on TTL
        let enriched: Vec<_> = flows.into_iter().map(|f| {
            let state_ttl_pct = f.state_ttl_percentage();
            let status = match state_ttl_pct {
                p if p > 80.0 => FlowHealth::Critical,  // 🔴
                p if p > 50.0 => FlowHealth::Warning,   // 🟡
                _ => FlowHealth::Healthy,                // 🟢
            };
            ActiveFlowView { flow: f, health: status }
        }).collect();

        // Aggregate summary
        let summary = FlowSummary::from_flows(&enriched);

        // Detect anomalies for alerts
        let alerts = self.detect_anomalies(&enriched);

        Ok(ActiveFlowSnapshot {
            flows: enriched,
            summary,
            alerts,
        })
    }

    fn detect_anomalies(&self, flows: &[ActiveFlowView]) -> Vec<Alert> {
        let mut alerts = Vec::new();

        // Detect IP-based clustering (possible credential stuffing)
        let by_ip = flows.iter().fold(
            HashMap::<IpAddr, usize>::new(),
            |mut acc, f| { *acc.entry(f.flow.client_ip).or_default() += 1; acc }
        );
        for (ip, count) in &by_ip {
            if *count >= 5 {
                alerts.push(Alert::HighFlowRate {
                    ip: *ip,
                    count: *count,
                    window: Duration::from_secs(60),
                });
            }
        }

        // Detect all OIDC flows stuck in redirect
        let stuck_oidc: Vec<_> = flows.iter()
            .filter(|f| f.flow.flow_type == "oidc"
                && f.flow.current_state == "redirect_pending")
            .collect();
        if stuck_oidc.len() >= 3 {
            alerts.push(Alert::PossibleProviderOutage {
                provider: "oidc".into(),
                stuck_count: stuck_oidc.len(),
            });
        }

        // Detect flows near timeout
        for f in flows {
            if matches!(f.health, FlowHealth::Critical) {
                alerts.push(Alert::FlowNearTimeout {
                    flow_id: f.flow.flow_id.clone(),
                    state: f.flow.current_state.to_string(),
                    ttl_remaining: f.flow.state_time_remaining(),
                });
            }
        }

        alerts
    }
}

pub struct TimeoutExtension {
    pub new_flow_expiry: Instant,
    pub new_state_expiry: Instant,
}

pub struct ActiveFlowFilter {
    pub project_id: ProjectId,
    pub tenant_id: Option<TenantId>,
    pub flow_type: Option<String>,
    pub state: Option<String>,
    pub ip_prefix: Option<String>,
}

pub enum FlowHealth {
    Healthy,    // 🟢 <50% of state TTL
    Warning,    // 🟡 50-80% of state TTL
    Critical,   // 🔴 >80% of state TTL
}

pub enum Alert {
    HighFlowRate { ip: IpAddr, count: usize, window: Duration },
    PossibleProviderOutage { provider: String, stuck_count: usize },
    FlowNearTimeout { flow_id: FlowId, state: String, ttl_remaining: Duration },
}
```

---

## Config Reconciler

The reconciler translates declarative auth config into Cognito API calls. It computes diffs and applies changes in dependency order.

```rust
pub struct ConfigReconciler {
    cognito: CognitoAdmin,
    lambda_manager: LambdaManager,
    ses: SesManager,
    sns: SnsManager,
    dynamo: DynamoManager,
    iam: IamManager,
}

impl ConfigReconciler {
    pub async fn reconcile(
        &self,
        desired: &AuthConfig,
        current: &CurrentState,
    ) -> Result<ReconciliationReport, ReconcileError> {
        let plan = self.compute_plan(desired, current)?;
        let ordered = plan.topological_sort();

        let mut report = ReconciliationReport::new();

        for step in ordered {
            match self.execute_step(&step).await {
                Ok(result) => report.record_success(step, result),
                Err(e) => {
                    report.record_failure(step, &e);
                    // Rollback completed steps in reverse
                    self.rollback(&report).await?;
                    return Err(ReconcileError::StepFailed {
                        step,
                        cause: e,
                        report,
                    });
                }
            }
        }

        Ok(report)
    }
}

/// Each step has explicit dependencies and a rollback action.
pub enum ReconcileStep {
    // ── Prerequisites ──
    VerifySesIdentity { email: Email },
    ConfigureSnsTopic,
    CreateIamRole { role_name: String, policy: IamPolicy },
    CreateDynamoTable { table_name: String, ttl_attribute: String },

    // ── Lambda triggers ──
    DeployLambda { function_name: String, handler: LambdaHandler, config: Value },
    AttachCognitoTrigger { trigger_type: TriggerType, lambda_arn: String },

    // ── Cognito user pool config ──
    UpdateMfaConfig { mode: MfaMode, methods: Vec<MfaMethod> },
    UpdatePasswordPolicy { policy: PasswordPolicy },
    CreateIdentityProvider { provider: ProviderConfig },
    UpdateIdentityProvider { provider: ProviderConfig },
    DeleteIdentityProvider { provider_name: String },

    // ── Cognito app client ──
    UpdateAppClient { auth_flows: Vec<AuthFlowType>, token_expiry: TokenExpiry },
    UpdateCallbackUrls { urls: Vec<Url> },
}

impl ReconcileStep {
    /// Explicit dependency ordering.
    pub fn depends_on(&self) -> Vec<ReconcileStep> {
        match self {
            // Lambda deploy needs IAM role first
            Self::DeployLambda { .. } => vec![Self::CreateIamRole { .. }],
            // Trigger attachment needs Lambda deployed
            Self::AttachCognitoTrigger { lambda_arn, .. } =>
                vec![Self::DeployLambda { function_name: lambda_arn.clone(), .. }],
            // SMS MFA needs SNS configured
            Self::UpdateMfaConfig { methods, .. } if methods.contains(&MfaMethod::Sms) =>
                vec![Self::ConfigureSnsTopic],
            // Magic link needs SES + DynamoDB + Lambda
            // ... etc
            _ => vec![],
        }
    }
}
```

---

## Cognito Adapter

The adapter translates between ForgeGate's typed domain and the AWS SDK's stringly-typed Cognito API.

```rust
pub struct CognitoAdapter {
    client: aws_sdk_cognitoidentityprovider::Client,
    user_pool_id: String,
    app_client_id: String,
}

impl CognitoAdapter {
    pub async fn initiate_auth(
        &self,
        ctx: &FlowContext,
        flow: AuthFlow,
        params: &[(&str, &str)],
    ) -> Result<CognitoAuthResult, CognitoError> {
        let mut auth_params = HashMap::new();
        for (k, v) in params {
            auth_params.insert(k.to_string(), v.to_string());
        }

        let response = self.client
            .initiate_auth()
            .client_id(&self.app_client_id)
            .auth_flow(flow.to_cognito())
            .set_auth_parameters(Some(auth_params))
            .send()
            .await?;

        // Map Cognito's untyped response into our typed result
        match response.challenge_name() {
            None => {
                // No challenge — auth complete
                let result = response.authentication_result()
                    .ok_or(CognitoError::MissingAuthResult)?;
                Ok(CognitoAuthResult::Success(TokenSet {
                    access_token: result.access_token().unwrap().into(),
                    id_token: result.id_token().unwrap().into(),
                    refresh_token: result.refresh_token().unwrap().into(),
                    expires_in: Duration::from_secs(
                        result.expires_in() as u64
                    ),
                }))
            }
            Some(challenge) => {
                let session = response.session().unwrap().to_string();
                match challenge.as_str() {
                    "SMS_MFA" => Ok(CognitoAuthResult::MfaChallenge {
                        session: CognitoSession(session),
                        mfa_method: MfaMethod::Sms,
                    }),
                    "SOFTWARE_TOKEN_MFA" => Ok(CognitoAuthResult::MfaChallenge {
                        session: CognitoSession(session),
                        mfa_method: MfaMethod::Totp,
                    }),
                    "CUSTOM_CHALLENGE" => Ok(CognitoAuthResult::CustomChallenge {
                        session: CognitoSession(session),
                    }),
                    "NEW_PASSWORD_REQUIRED" => Ok(CognitoAuthResult::NewPasswordRequired {
                        session: CognitoSession(session),
                    }),
                    other => Err(CognitoError::UnknownChallenge(other.into())),
                }
            }
        }
    }
}
```

---

## Testing Strategy

The typestate pattern makes testing straightforward — each state and transition is individually testable, and the compiler prevents testing invalid transitions.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Mock Cognito adapter for testing
    fn mock_cognito() -> CognitoAdapter {
        CognitoAdapter::mock()
            .with_user("test@example.com", "password123")
            .with_mfa_enabled("test@example.com", MfaMethod::Totp)
            .build()
    }

    #[tokio::test]
    async fn password_flow_without_mfa() {
        let flow = PasswordFlow::new(test_ctx(), mock_cognito_no_mfa());

        let result = flow.submit_credentials(
            &"test@example.com".into(),
            &"password123".into(),
        ).await.unwrap();

        // Compiler forces us to handle both branches
        match result {
            PasswordAfterCredentials::Authenticated(flow) => {
                let success = flow.complete().await.unwrap();
                assert_eq!(success.user_id.as_str(), "user_123");
            }
            PasswordAfterCredentials::MfaRequired(_) => {
                panic!("Expected no MFA");
            }
        }
    }

    #[tokio::test]
    async fn password_flow_with_mfa() {
        let flow = PasswordFlow::new(test_ctx(), mock_cognito());

        let result = flow.submit_credentials(
            &"test@example.com".into(),
            &"password123".into(),
        ).await.unwrap();

        match result {
            PasswordAfterCredentials::MfaRequired(flow) => {
                assert_eq!(*flow.mfa_method(), MfaMethod::Totp);

                let flow = flow.submit_mfa(&"123456".into()).await.unwrap();
                let success = flow.complete().await.unwrap();
                assert_eq!(success.user_id.as_str(), "user_123");
            }
            _ => panic!("Expected MFA required"),
        }
    }

    #[tokio::test]
    async fn magic_link_flow_complete() {
        let flow = MagicLinkFlow::new(
            test_ctx(), mock_cognito_no_mfa(),
            mock_challenges(), mock_mailer(),
            test_magic_link_config(),
        );

        let flow = flow.request_link(&"test@example.com".into())
            .await.unwrap();
        assert!(flow.time_remaining() > Duration::ZERO);

        // Retrieve the code that was stored
        let code = mock_challenges().get_last_code();

        match flow.verify_code(&code).await.unwrap() {
            MagicLinkAfterVerify::Verified(flow) => {
                let success = flow.complete().await.unwrap();
                assert!(success.tokens.access_token.len() > 0);
            }
            _ => panic!("Expected verified, not MFA"),
        }
    }

    // This test DOES NOT COMPILE — which is the point.
    // Uncomment to verify the compiler catches invalid transitions.
    //
    // #[tokio::test]
    // async fn cannot_submit_mfa_on_initiated_flow() {
    //     let flow = PasswordFlow::new(test_ctx(), mock_cognito());
    //     // ERROR: no method named `submit_mfa` found for
    //     // `PasswordFlow<password::Initiated>`
    //     flow.submit_mfa(&"123456".into()).await;
    // }
}
```

---

## Summary: What Rust + State Machines + Event Log Give Us

| Property | How It's Achieved |
|----------|------------------|
| Invalid transitions are impossible | Typestate encoding — methods only exist on valid states |
| All branches are handled | `enum` return types force exhaustive matching |
| No forgotten states | Compiler error if a match arm is missing |
| Memory safety | Rust ownership — no use-after-free, no data races |
| Flows cannot hang indefinitely | Two-level timeouts: flow-level max lifetime + per-state timeouts, enforced before every transition |
| Abandoned flows are cleaned up | FlowReaper background task scans and terminates expired flows, cleaning up side-effect resources |
| Full traceability | Append-only event log records every transition (including timeouts) with timestamps, durations, and side effects |
| Per-transition metrics | Every state change emits histograms and counters (latency, throughput, failure rate, timeout rate) |
| Side effect visibility | Every external call (Cognito, SES, SNS, DynamoDB) is individually timed and recorded |
| Flow replay | Any authentication attempt can be inspected step-by-step in the dashboard Flow Inspector |
| Failure forensics | Failed and timed-out flows record the exact state, error, and side effect that caused the failure |
| Compliance audit trail | Event logs are append-only, immutable, archived to S3 for long-term retention |
| Performance optimization | Metrics pinpoint exactly which transition or side effect is the bottleneck |
| Testability | Each state is a type, each transition is a function, mock side effects via the collector |
| Auditability | State diagrams map directly to code — reviewers read types, auditors read event logs |
| Performance | Zero-cost abstractions — state types are compile-time only, recorder overhead is sub-microsecond |
| Secret handling | `SecretString` / `Zeroize` — passwords cleared from memory, never written to event logs |

The Identity Engine doesn't hope that auth flows are correct — it proves it at compile time. It doesn't hope that operations are observable — it records every transition by construction. And it doesn't hope that flows terminate — it enforces it with timeouts at every level.

---

## Related Documents

- [Control Plane UI Design](08-technical-control-plane-ui.md) — God Mode and Flow Inspector that consume the event log
- [SDK Architecture](13-technical-sdk-architecture-conformance.md) — how the Rust core is distributed as SDKs
- [Multi-Region & DR](04-multi-region-dr-architecture.md) — how Cognito limitations affect failover
- [Self-Hosted Data Plane](03-technical-self-hosted-data-plane.md) — where the Identity Engine runs in self-hosted mode
