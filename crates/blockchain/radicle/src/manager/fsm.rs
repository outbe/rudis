use super::types::{ManagerPhase, PhaseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseMode {
    FullNodeDisabled,
    Validator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseInput {
    pub mode: PhaseMode,
    pub sidecar_available: bool,
    pub local_node_id: Option<[u8; 32]>,
    pub finalized_binding: Option<[u8; 32]>,
    pub was_ready: bool,
}

pub fn evaluate_phase(input: PhaseInput) -> Result<ManagerPhase, PhaseError> {
    if input.mode == PhaseMode::FullNodeDisabled {
        return Ok(ManagerPhase::Disabled);
    }
    if !input.sidecar_available {
        return if input.was_ready {
            Ok(ManagerPhase::RuntimeDegraded)
        } else {
            Err(PhaseError::SidecarUnavailable)
        };
    }
    let local = input
        .local_node_id
        .ok_or(PhaseError::LocalNodeIdUnavailable)?;
    match input.finalized_binding {
        None => Ok(ManagerPhase::JoiningUnbound),
        Some(binding) if binding == local => Ok(ManagerPhase::Ready),
        Some(_) => Err(PhaseError::BindingMismatch),
    }
}
