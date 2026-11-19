use serde::{Deserialize, Serialize};
use thiserror::Error;
use wardline_core::IsolationLevel;

use crate::{
    probe_capabilities, spawn_isolated, GvisorBackend, FirecrackerBackend, HcsBackend, VzBackend,
    HostCapabilitiesRaw, SpawnConfig, SpawnOutput,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SandboxInitError {
    #[error("required isolation tier {required:?} is unavailable on this host: {reason}")]
    IsolationUnavailable {
        required: IsolationLevel,
        reason: String,
    },
    #[error("policy forbids unisolated execution")]
    PolicyForbidsUnisolated,
    #[error("invalid sandbox driver configuration: {0}")]
    InvalidConfig(String),
    #[error("golden guest image verification failed: {0}")]
    ImageVerificationFailed(String),
}

pub trait IsolationBackend: Send + Sync {
    fn tier(&self) -> IsolationLevel;

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError>;

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError>;

    fn teardown(&mut self);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeEngineBackend {
    pub target_tier: IsolationLevel,
}

impl IsolationBackend for NativeEngineBackend {
    fn tier(&self) -> IsolationLevel {
        self.target_tier
    }

    fn honors(
        &self,
        required: IsolationLevel,
        caps: &HostCapabilitiesRaw,
    ) -> Result<(), SandboxInitError> {
        if required == IsolationLevel::Unisolated {
            return Err(SandboxInitError::PolicyForbidsUnisolated);
        }
        if self.target_tier < required {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: format!(
                    "backend tier {:?} is weaker than required {:?}",
                    self.target_tier, required
                ),
            });
        }
        if required == IsolationLevel::L2 {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: "L2 requires dedicated Firecracker/HCS/Virtualization MicroVM driver".into(),
            });
        }
        if !caps.supports_tier(required) {
            return Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: format!(
                    "host OS={} tier_mask=0x{:x} does not support {:?}",
                    caps.os_name(),
                    caps.tier_support_mask,
                    required
                ),
            });
        }
        Ok(())
    }

    fn execute(&self, cfg: &SpawnConfig) -> Result<SpawnOutput, SandboxInitError> {
        if cfg.isolation == IsolationLevel::Unisolated && !cfg.allow_unisolated {
            return Err(SandboxInitError::PolicyForbidsUnisolated);
        }
        let caps = probe_capabilities().map_err(|rc| SandboxInitError::IsolationUnavailable {
            required: cfg.isolation,
            reason: format!("capability probe failed with status {rc}"),
        })?;
        self.honors(cfg.isolation, &caps)?;
        Ok(spawn_isolated(cfg))
    }

    fn teardown(&mut self) {}
}

/// Fail-closed isolation driver selector. Never downgrades a stronger required tier to a weaker one.
pub fn select_backend_for_tier(
    required: IsolationLevel,
    caps: &HostCapabilitiesRaw,
) -> Result<Box<dyn IsolationBackend>, SandboxInitError> {
    match required {
        IsolationLevel::Unisolated => Err(SandboxInitError::PolicyForbidsUnisolated),
        IsolationLevel::L0 | IsolationLevel::L1 => {
            let b = NativeEngineBackend {
                target_tier: required,
            };
            b.honors(required, caps)?;
            Ok(Box::new(b))
        }
        IsolationLevel::L1_5 => {
            if caps.os_kind == 2 {
                let b = GvisorBackend::default();
                b.honors(IsolationLevel::L1_5, caps)?;
                Ok(Box::new(b))
            } else {
                let b = NativeEngineBackend {
                    target_tier: IsolationLevel::L1_5,
                };
                b.honors(IsolationLevel::L1_5, caps)?;
                Ok(Box::new(b))
            }
        }
        IsolationLevel::L2 => match caps.os_kind {
            1 => {
                let b = HcsBackend::default();
                b.honors(IsolationLevel::L2, caps)?;
                Ok(Box::new(b))
            }
            2 => {
                let b = FirecrackerBackend::default();
                b.honors(IsolationLevel::L2, caps)?;
                Ok(Box::new(b))
            }
            3 => {
                let b = VzBackend::default();
                b.honors(IsolationLevel::L2, caps)?;
                Ok(Box::new(b))
            }
            _ => Err(SandboxInitError::IsolationUnavailable {
                required,
                reason: format!("no L2 MicroVM hypervisor driver on OS={}", caps.os_name()),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_caps(os_kind: u8, tier_mask: u32) -> HostCapabilitiesRaw {
        HostCapabilitiesRaw {
            struct_size: 48,
            abi_version: 2,
            arch: 1,
            os_build_number: 26300,
            page_size: 4096,
            tier_support_mask: tier_mask,
            feature_flags: 0,
            is_wow64_emulated: 0,
            cet_shadow_stack_supported: 0,
            pac_bti_available: 0,
            hyperv_hcs_available: u8::from((tier_mask & crate::TIER_BIT_L2) != 0),
            appcontainer_supported: u8::from((tier_mask & crate::TIER_BIT_L1) != 0),
            job_object_iocp_supported: 1,
            os_kind,
            arm64_ext_flags: 0,
            landlock_abi: 0,
            cgroup_v2_available: 0,
            reserved: [0; 6],
        }
    }

    #[test]
    fn fail_closed_honors_prevents_silent_downgrade() {
        let l0_only = fake_caps(2, crate::TIER_BIT_L0);
        let l1_backend = NativeEngineBackend {
            target_tier: IsolationLevel::L1,
        };
        assert!(matches!(
            l1_backend.honors(IsolationLevel::L1, &l0_only),
            Err(SandboxInitError::IsolationUnavailable {
                required: IsolationLevel::L1,
                ..
            })
        ));
        assert!(matches!(
            select_backend_for_tier(IsolationLevel::L2, &l0_only),
            Err(SandboxInitError::IsolationUnavailable {
                required: IsolationLevel::L2,
                ..
            })
        ));
        assert!(matches!(
            select_backend_for_tier(IsolationLevel::Unisolated, &l0_only),
            Err(SandboxInitError::PolicyForbidsUnisolated)
        ));
    }
}
