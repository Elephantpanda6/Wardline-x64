use serde::{Deserialize, Serialize};

use crate::manifest::EgressMode;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPhaseConfig {
    #[serde(default)]
    pub egress_mode: Option<EgressMode>,
    #[serde(default)]
    pub allowed_destinations: Vec<String>,
    #[serde(default)]
    pub allow_binaries: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    #[serde(default)]
    pub setup: Option<SessionPhaseConfig>,
    #[serde(default)]
    pub run: Option<SessionPhaseConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    Setup,
    Run,
}

/// Enforces one-way transition `Setup -> Run` so an active run phase can never reopen setup network scopes.
#[derive(Debug, Clone)]
pub struct SessionState {
    phase: SessionPhase,
}

impl SessionState {
    pub fn new(initial: SessionPhase) -> Self {
        Self { phase: initial }
    }

    pub fn current(&self) -> SessionPhase {
        self.phase
    }

    pub fn advance_to_run(&mut self) -> Result<(), String> {
        match self.phase {
            SessionPhase::Setup => {
                self.phase = SessionPhase::Run;
                Ok(())
            }
            SessionPhase::Run => Ok(()),
        }
    }

    pub fn transition(&mut self, next: SessionPhase) -> Result<(), String> {
        match (self.phase, next) {
            (SessionPhase::Run, SessionPhase::Setup) => {
                Err("cannot transition session backwards from Run to Setup phase".into())
            }
            _ => {
                self.phase = next;
                Ok(())
            }
        }
    }
}
