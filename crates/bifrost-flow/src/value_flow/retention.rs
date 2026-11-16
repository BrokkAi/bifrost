//! Request capabilities over the existing core retention authorities.

use brokk_bifrost_core::analyzer::outer_request::{
    OuterRequest, RequestEntryKey, RequestResource, RequestResourceError,
};
use brokk_bifrost_core::retention_budget::{RetentionBudget, SharedBackingLease};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// The existing registration plan/artifact limits, shared by all cloned holders.
/// This capability adds no allocation ledger or independent byte allowance.
#[derive(Clone)]
pub struct ValueFlowRetentionBudget(Arc<RetentionAuthorities>);

struct RetentionAuthorities {
    id: u64,
    plan: RetentionBudget,
    artifact: RetentionBudget,
}

impl ValueFlowRetentionBudget {
    pub fn new(plan_bytes: usize, artifact_bytes: usize) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(id, 0, "value-flow retention identity exhausted");
        Self(Arc::new(RetentionAuthorities {
            id,
            plan: RetentionBudget::new(plan_bytes as u64),
            artifact: RetentionBudget::new(artifact_bytes as u64),
        }))
    }

    pub fn scope_id(&self) -> u64 {
        self.0.id
    }
    pub fn plan_limit_bytes(&self) -> usize {
        self.0.plan.capacity_bytes() as usize
    }
    pub fn artifact_limit_bytes(&self) -> usize {
        self.0.artifact.capacity_bytes() as usize
    }
    pub fn retained_plan_bytes(&self) -> usize {
        usize::try_from(self.0.plan.accounted_bytes()).unwrap_or(usize::MAX)
    }
    pub fn retained_artifact_bytes(&self) -> usize {
        usize::try_from(self.0.artifact.accounted_bytes()).unwrap_or(usize::MAX)
    }
    pub fn plan_allocation(&self, bytes: usize) -> Option<SharedBackingLease> {
        self.0.plan.shared_backing(bytes as u64)
    }
    /// Full artifacts remain conservatively charged per registration. Exact
    /// factory artifact holders can additionally retain keyed backing charges
    /// under this SAME limit; they never reduce ordinary registration charges.
    pub fn artifact_allocation(&self, bytes: usize) -> Option<SharedBackingLease> {
        self.0.artifact.shared_backing(bytes as u64)
    }
    pub fn plan_backing(&self, allocation: usize, bytes: usize) -> Option<SharedBackingLease> {
        self.0.plan.shared_backing_for(allocation, bytes as u64)
    }
    pub fn artifact_backing(&self, allocation: usize, bytes: usize) -> Option<SharedBackingLease> {
        self.0.artifact.shared_backing_for(allocation, bytes as u64)
    }
}

impl fmt::Debug for ValueFlowRetentionBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueFlowRetentionBudget")
            .field("scope_id", &self.scope_id())
            .field("plan_bytes", &self.retained_plan_bytes())
            .field("artifact_bytes", &self.retained_artifact_bytes())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFlowRetentionScopeError {
    Closed,
    BudgetMismatch,
}
impl fmt::Display for ValueFlowRetentionScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "value-flow retention request is closed",
            Self::BudgetMismatch => {
                "outer request already has another value-flow retention authority"
            }
        })
    }
}
impl std::error::Error for ValueFlowRetentionScopeError {}

/// Capture-safe authority for one outer request. The scope retains no factory,
/// plans or artifacts. Closing refuses new charges; existing leases stay live.
#[derive(Debug)]
pub struct ValueFlowRetentionScope {
    budget: ValueFlowRetentionBudget,
    request_id: u64,
    request: Weak<OuterRequest>,
    closed: Mutex<bool>,
}

impl ValueFlowRetentionScope {
    pub fn bind(
        request: &Arc<OuterRequest>,
        budget: &ValueFlowRetentionBudget,
    ) -> Result<Arc<Self>, ValueFlowRetentionScopeError> {
        let scope = request
            .resource(RequestEntryKey::ValueFlowRetention, || {
                Ok::<_, ()>(Arc::new(Self {
                    budget: budget.clone(),
                    request_id: request.id(),
                    request: Arc::downgrade(request),
                    closed: Mutex::new(false),
                }))
            })
            .map_err(|error| match error {
                RequestResourceError::Closed => ValueFlowRetentionScopeError::Closed,
                RequestResourceError::Open(()) => unreachable!("scope construction is infallible"),
            })?;
        if scope.is_closed() {
            return Err(ValueFlowRetentionScopeError::Closed);
        }
        if scope.scope_id() != budget.scope_id() {
            return Err(ValueFlowRetentionScopeError::BudgetMismatch);
        }
        Ok(scope)
    }

    /// Read an already-bound capability without allocating a resource slot,
    /// budget or transient request. Generic outer-resource storage remains
    /// outside this capability's payload budgets.
    pub fn current(request: &Arc<OuterRequest>) -> Option<Arc<Self>> {
        request.resource_if_present(&RequestEntryKey::ValueFlowRetention)
    }
    pub fn scope_id(&self) -> u64 {
        self.budget.scope_id()
    }
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn plan_limit_bytes(&self) -> usize {
        self.budget.plan_limit_bytes()
    }
    pub fn artifact_limit_bytes(&self) -> usize {
        self.budget.artifact_limit_bytes()
    }
    pub fn is_closed(&self) -> bool {
        *self.closed.lock().expect("retention scope poisoned")
            || self
                .request
                .upgrade()
                .is_none_or(|request| request.is_closed())
    }
    pub fn outer_request(&self) -> Result<Arc<OuterRequest>, ValueFlowRetentionScopeError> {
        if self.is_closed() {
            return Err(ValueFlowRetentionScopeError::Closed);
        }
        let request = self
            .request
            .upgrade()
            .ok_or(ValueFlowRetentionScopeError::Closed)?;
        if request.is_closed() {
            return Err(ValueFlowRetentionScopeError::Closed);
        }
        Ok(request)
    }
    fn admit(
        &self,
        charge: impl FnOnce(&ValueFlowRetentionBudget) -> Option<SharedBackingLease>,
    ) -> Option<SharedBackingLease> {
        let request = self.request.upgrade()?;
        let closed = self.closed.lock().expect("retention scope poisoned");
        if *closed || request.is_closed() {
            return None;
        }
        charge(&self.budget)
    }
    pub fn plan_allocation(&self, bytes: usize) -> Option<SharedBackingLease> {
        self.admit(|budget| budget.plan_allocation(bytes))
    }
    pub fn artifact_allocation(&self, bytes: usize) -> Option<SharedBackingLease> {
        self.admit(|budget| budget.artifact_allocation(bytes))
    }
    pub fn plan_backing(&self, allocation: usize, bytes: usize) -> Option<SharedBackingLease> {
        self.admit(|budget| budget.plan_backing(allocation, bytes))
    }
    pub fn artifact_backing(&self, allocation: usize, bytes: usize) -> Option<SharedBackingLease> {
        self.admit(|budget| budget.artifact_backing(allocation, bytes))
    }
}
impl RequestResource for ValueFlowRetentionScope {
    fn close(&self) {
        *self.closed.lock().expect("retention scope poisoned") = true;
    }
}

#[cfg(test)]
mod allocated_bytes_r_pins {
    use super::*;
    #[test]
    fn refusing_plan_and_artifact_charges_keep_master_bytes() {
        let budget = ValueFlowRetentionBudget::new(1 << 20, 1 << 20);
        let plan = budget.plan_allocation(100).expect("plan");
        let plan_backing = budget.plan_backing(7, 128).expect("plan backing");
        let artifact = budget.artifact_allocation(200).expect("artifact");
        let artifact_backing = budget.artifact_backing(8, 256).expect("artifact backing");
        // Master: payload plus the old512B keyed backing metadata, not the
        // evictable region's new704B allowance or allocation-size rounding.
        assert_eq!(budget.retained_plan_bytes(), 740);
        assert_eq!(budget.retained_artifact_bytes(), 968);
        assert_eq!(plan.bytes(), 100);
        assert_eq!(artifact.bytes(), 200);
        assert_eq!(plan_backing.bytes(), 128);
        assert_eq!(artifact_backing.bytes(), 256);
        drop((plan, plan_backing, artifact, artifact_backing));
        assert_eq!(budget.retained_plan_bytes(), 0);
        assert_eq!(budget.retained_artifact_bytes(), 0);
    }
}
