// Copyright 2025 Erst Users
// SPDX-License-Identifier: Apache-2.0

use soroban_env_host::{
    budget::Budget,
    storage::Storage,
    xdr::{Hash, ScErrorCode, ScErrorType},
    DiagnosticLevel, Error as EnvError, Host, HostError, TryIntoVal, Val,
};

/// Wrapper around the Soroban Host to manage initialization and execution context.
pub struct SimHost {
    pub inner: Host,
    pub _contract_id: Option<Hash>,
    pub _fn_name: Option<String>,
}

impl SimHost {
    /// Initialize a new Host with optional budget settings.
    ///
    /// Resource calibration via `CostModel` is not available in the public API
    /// of soroban-env-host v25; custom cost parameters require the `testutils`
    /// feature which is not enabled in production builds. The `calibration`
    /// argument is accepted for API compatibility but is intentionally unused.
    pub fn new(
        _budget_limits: Option<(u64, u64)>,
        _calibration: Option<crate::types::ResourceCalibration>,
    ) -> Self {
        let budget = Budget::default();
        let host = Host::with_storage_and_budget(Storage::default(), budget);

        host.set_diagnostic_level(DiagnosticLevel::Debug)
            .expect("failed to set diagnostic level");

        Self {
            inner: host,
            _contract_id: None,
            _fn_name: None,
        }
    }

    /// Set the contract ID for execution context.
    pub fn _set_contract_id(&mut self, id: Hash) {
        self._contract_id = Some(id);
    }

    /// Set the function name to invoke.
    pub fn _set_fn_name(&mut self, name: &str) -> Result<(), HostError> {
        self._fn_name = Some(name.to_string());
        Ok(())
    }

    /// Convert a u32 to a Soroban Val.
    pub fn _val_from_u32(&self, v: u32) -> Val {
        Val::from_u32(v).into()
    }

    /// Convert a Val back to u32.
    pub fn _val_to_u32(&self, v: Val) -> Result<u32, HostError> {
        v.try_into_val(&self.inner).map_err(|_| {
            EnvError::from_type_and_code(ScErrorType::Context, ScErrorCode::InvalidInput).into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_initialization() {
        let host = SimHost::new(None, None);
        assert!(host.inner.budget_cloned().get_cpu_insns_consumed().is_ok());
    }

    #[test]
    fn test_configuration() {
        let mut host = SimHost::new(None, None);
        let hash = Hash([0u8; 32]);
        host._set_contract_id(hash);
        assert!(host._contract_id.is_some());

        host._set_fn_name("add").expect("failed to set function name");
        assert!(host._fn_name.is_some());
    }

    #[test]
    fn test_simple_value_handling() {
        let host = SimHost::new(None, None);

        let val_a = host._val_from_u32(10);
        let val_b = host._val_from_u32(20);

        let res_a = host._val_to_u32(val_a).expect("conversion failed");
        let res_b = host._val_to_u32(val_b).expect("conversion failed");

        assert_eq!(res_a + res_b, 30);
    }
}