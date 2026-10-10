//! Hatter downstream 2026: orchestration identity, never OS mechanism or domain truth.
use serde::{Deserialize, Serialize};

pub const MAX_HANDSHAKE_BYTES: usize = 4096;
/// Exact physical handshake only; no domain request is carried or replayed.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeRequest {
    pub expected: OwnerProcessRef,
    pub owner_type: OwnerType,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerProcessRef {
    pub owner_ref: String,
    pub incarnation: [u8; 32],
    pub protocol_generation: [u8; 32],
    pub executable_identity: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    InvalidIdentity,
    EntropyUnavailable,
    InvalidFrame,
    FrameTooLarge,
    OwnerMismatch,
    StaleIncarnation,
    ProtocolMismatch,
    ExecutableMismatch,
    OwnerTypeMismatch,
    InvalidAvailability,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Failure {}
impl OwnerProcessRef {
    /// Only orchestration issues physical incarnations. No PID/counter input exists.
    pub fn issue(
        owner_ref: String,
        protocol_generation: [u8; 32],
        executable_identity: [u8; 32],
    ) -> Result<Self, Failure> {
        let mut incarnation = [0; 32];
        getrandom::fill(&mut incarnation).map_err(|_| Failure::EntropyUnavailable)?;
        let value = Self {
            owner_ref,
            incarnation,
            protocol_generation,
            executable_identity,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Failure> {
        if self.owner_ref.is_empty()
            || self.owner_ref.len() > 512
            || self
                .owner_ref
                .bytes()
                .any(|c| c.is_ascii_control() || c == b' ')
            || self.incarnation == [0; 32]
            || self.protocol_generation == [0; 32]
            || self.executable_identity == [0; 32]
        {
            return Err(Failure::InvalidIdentity);
        }
        Ok(())
    }
    pub fn verify(&self, actual: &Self) -> Result<(), Failure> {
        self.validate()?;
        actual.validate()?;
        if self.owner_ref != actual.owner_ref {
            return Err(Failure::OwnerMismatch);
        }
        if self.incarnation != actual.incarnation {
            return Err(Failure::StaleIncarnation);
        }
        if self.protocol_generation != actual.protocol_generation {
            return Err(Failure::ProtocolMismatch);
        }
        if self.executable_identity != actual.executable_identity {
            return Err(Failure::ExecutableMismatch);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerType {
    Management,
    Graph,
    Semantic,
    Inference,
    EvidenceSigning,
    EvidenceLookup,
    Provider,
    Projection,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartPolicy {
    StatelessAutoRestart,
    SafeOwnerRestart,
    ReconciliationRequired,
    NoAutomaticRestart,
}
impl RestartPolicy {
    pub fn physical_restart_allowed(self) -> bool {
        matches!(self, Self::StatelessAutoRestart | Self::SafeOwnerRestart)
    }
}
impl OwnerType {
    pub fn initial_restart_policy(self) -> RestartPolicy {
        match self {
            Self::Graph => RestartPolicy::SafeOwnerRestart,
            Self::Projection => RestartPolicy::StatelessAutoRestart,
            Self::EvidenceSigning | Self::EvidenceLookup => RestartPolicy::NoAutomaticRestart,
            _ => RestartPolicy::ReconciliationRequired,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnavailableCause {
    Missing,
    Corrupt,
    StorageFailure,
    RecoveryRequired,
    ProcessExited,
    TransportLost,
    HandshakeRejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerReady {
    Starting,
    Recovering,
    Ready,
    Unavailable(UnavailableCause),
}
/// Volatile observations, not domain state. Empty/uncertain/resolution aren't readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Availability {
    pub process_alive: bool,
    pub transport_available: bool,
    pub owner_ready: OwnerReady,
    pub domain_dispatch_available: bool,
}
impl Availability {
    pub fn validate(&self) -> Result<(), Failure> {
        if (self.transport_available && !self.process_alive)
            || (self.domain_dispatch_available
                && (!self.process_alive
                    || !self.transport_available
                    || self.owner_ready != OwnerReady::Ready))
        {
            return Err(Failure::InvalidAvailability);
        }
        Ok(())
    }
    pub fn process_lost(&mut self) {
        self.process_alive = false;
        self.transport_available = false;
        self.owner_ready = OwnerReady::Unavailable(UnavailableCause::ProcessExited);
        self.domain_dispatch_available = false;
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub process: OwnerProcessRef,
    pub owner_type: OwnerType,
    pub availability: Availability,
}
impl Handshake {
    /// Crowsi framing must enforce this same bound before allocation. This second
    /// boundary prevents direct in-process callers bypassing contract admission.
    pub fn decode_exact(
        bytes: &[u8],
        expected: &OwnerProcessRef,
        owner_type: OwnerType,
    ) -> Result<Self, Failure> {
        if bytes.len() > MAX_HANDSHAKE_BYTES {
            return Err(Failure::FrameTooLarge);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Failure::InvalidFrame)?;
        expected.verify(&value.process)?;
        if value.owner_type != owner_type {
            return Err(Failure::OwnerTypeMismatch);
        }
        value.availability.validate()?;
        if !value.availability.process_alive || !value.availability.transport_available {
            return Err(Failure::InvalidAvailability);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> OwnerProcessRef {
        OwnerProcessRef::issue("hatter/graph/control".into(), [1; 32], [2; 32]).unwrap()
    }
    #[test]
    fn exact_restart_handshake_rejects_stale_foreign_and_unknown_fields() {
        let expected = identity();
        let next = identity();
        assert_ne!(expected.incarnation, next.incarnation);
        let initial = Handshake {
            process: expected.clone(),
            owner_type: OwnerType::Graph,
            availability: Availability {
                process_alive: true,
                transport_available: true,
                owner_ready: OwnerReady::Recovering,
                domain_dispatch_available: false,
            },
        };
        let bytes = serde_json::to_vec(&initial).unwrap();
        assert_eq!(
            Handshake::decode_exact(&bytes, &expected, OwnerType::Graph).unwrap(),
            initial
        );
        assert_eq!(
            Handshake::decode_exact(&bytes, &next, OwnerType::Graph),
            Err(Failure::StaleIncarnation)
        );
        for (field, failure) in [
            ("owner_ref", Failure::OwnerMismatch),
            ("protocol_generation", Failure::ProtocolMismatch),
            ("executable_identity", Failure::ExecutableMismatch),
        ] {
            let mut v = initial.clone();
            match field {
                "owner_ref" => v.process.owner_ref = "other".into(),
                "protocol_generation" => v.process.protocol_generation = [3; 32],
                _ => v.process.executable_identity = [3; 32],
            }
            assert_eq!(
                Handshake::decode_exact(
                    &serde_json::to_vec(&v).unwrap(),
                    &expected,
                    OwnerType::Graph
                ),
                Err(failure)
            );
        }
        let mut value = serde_json::to_value(&initial).unwrap();
        value["pid"] = 42.into();
        assert_eq!(
            Handshake::decode_exact(
                &serde_json::to_vec(&value).unwrap(),
                &expected,
                OwnerType::Graph
            ),
            Err(Failure::InvalidFrame)
        );
        assert_eq!(
            Handshake::decode_exact(&vec![b' '; 4097], &expected, OwnerType::Graph),
            Err(Failure::FrameTooLarge)
        );
        assert_eq!(
            Handshake::decode_exact(&bytes, &expected, OwnerType::Semantic),
            Err(Failure::OwnerTypeMismatch)
        );
    }
    #[test]
    fn four_dimensions_and_policy_do_not_invent_domain_success() {
        for owner_ready in [
            OwnerReady::Starting,
            OwnerReady::Recovering,
            OwnerReady::Ready,
            OwnerReady::Unavailable(UnavailableCause::Missing),
            OwnerReady::Unavailable(UnavailableCause::Corrupt),
            OwnerReady::Unavailable(UnavailableCause::StorageFailure),
            OwnerReady::Unavailable(UnavailableCause::RecoveryRequired),
        ] {
            let mut v = Availability {
                process_alive: true,
                transport_available: true,
                owner_ready,
                domain_dispatch_available: false,
            };
            assert!(v.validate().is_ok());
            v.domain_dispatch_available = true;
            assert_eq!(v.validate().is_ok(), owner_ready == OwnerReady::Ready);
            v.process_lost();
            assert!(v.validate().is_ok());
            assert!(!v.domain_dispatch_available);
        }
        for owner in [
            OwnerType::Management,
            OwnerType::Graph,
            OwnerType::Semantic,
            OwnerType::Inference,
            OwnerType::EvidenceSigning,
            OwnerType::EvidenceLookup,
            OwnerType::Provider,
            OwnerType::Projection,
        ] {
            assert_eq!(
                owner.initial_restart_policy().physical_restart_allowed(),
                matches!(owner, OwnerType::Graph | OwnerType::Projection)
            );
        }
    }
}
