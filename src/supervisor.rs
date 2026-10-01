//! Hatter 2026: one volatile physical owner slot. No canonical stores or Work replay.
use crowsi_process_adapter::{Launch, OwnedProcess};
use crowsi_transport_foundation::{
    Connection, Limits,
    io::{Reader, Writer},
};
use hatter_owner_contracts::{
    Availability, Failure, Handshake, HandshakeRequest, MAX_HANDSHAKE_BYTES, OwnerProcessRef,
    OwnerReady, OwnerType, UnavailableCause,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read, path::PathBuf, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerSpec {
    pub owner_ref: String,
    pub owner_type: OwnerType,
    pub executable: PathBuf,
    pub executable_identity: [u8; 32],
    pub protocol_generation: [u8; 32],
    pub args: Vec<String>,
    /// Exact launch input. No inherited environment and no canonical state.
    pub environment: std::collections::BTreeMap<String, String>,
}
impl std::fmt::Debug for OwnerSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerSpec")
            .field("owner_ref", &self.owner_ref)
            .field("owner_type", &self.owner_type)
            .field("executable", &self.executable)
            .field("argument_count", &self.args.len())
            .field(
                "environment_keys",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub enum SupervisorError {
    InvalidSpec,
    ExecutableMismatch,
    Mechanism(crowsi_process_adapter::Error),
    Transport(crowsi_transport_foundation::Outcome),
    Contract(Failure),
    Io(std::io::Error),
    Deadline,
    TransportPoisoned,
    ControlUnavailable,
    RestartRequiresReconciliation,
}
impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSpec => "InvalidSpec",
            Self::ExecutableMismatch => "ExecutableMismatch",
            Self::Mechanism(_) => "ProcessMechanismFailed",
            Self::Transport(_) => "OwnerTransportUnavailable",
            Self::Contract(_) => "OwnerHandshakeRejected",
            Self::Io(_) => "OwnerIoUnavailable",
            Self::Deadline => "OwnerHandshakeDeadline",
            Self::TransportPoisoned => "OwnerTransportPoisoned",
            Self::ControlUnavailable => "OwnerControlUnavailable",
            Self::RestartRequiresReconciliation => "RestartRequiresReconciliation",
        })
    }
}
impl std::error::Error for SupervisorError {}
impl From<crowsi_process_adapter::Error> for SupervisorError {
    fn from(v: crowsi_process_adapter::Error) -> Self {
        Self::Mechanism(v)
    }
}
impl From<crowsi_transport_foundation::Outcome> for SupervisorError {
    fn from(v: crowsi_transport_foundation::Outcome) -> Self {
        Self::Transport(v)
    }
}
impl From<Failure> for SupervisorError {
    fn from(v: Failure) -> Self {
        Self::Contract(v)
    }
}
impl From<std::io::Error> for SupervisorError {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}

pub fn executable_digest(path: &std::path::Path) -> Result<[u8; 32], SupervisorError> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(SupervisorError::InvalidSpec);
    }
    let mut file = std::fs::File::open(path)?;
    // A reviewed executable is a regular, bounded artifact, never a pipe/device.
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 512 * 1024 * 1024 {
        return Err(SupervisorError::InvalidSpec);
    }
    let mut hash = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = file.read(&mut b)?;
        if n == 0 {
            break;
        }
        hash.update(&b[..n]);
    }
    Ok(hash.finalize().into())
}
async fn executable_digest_async(path: PathBuf) -> Result<[u8; 32], SupervisorError> {
    tokio::task::spawn_blocking(move || executable_digest(&path))
        .await
        .map_err(|_| SupervisorError::ControlUnavailable)?
}

pub fn wire_limits() -> Limits {
    Limits {
        accepted: MAX_HANDSHAKE_BYTES,
        buffered: MAX_HANDSHAKE_BYTES + 1,
        frame: MAX_HANDSHAKE_BYTES + 2,
        pending_bytes: (MAX_HANDSHAKE_BYTES + 2) * 2,
        pending_messages: 2,
    }
}

/// Compiled protocol capacity, never caller data or permission. Health retains
/// its separate handshake bound. One queue slot carries one bounded message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandBudget(usize);
impl CommandBudget {
    pub const STANDARD: Self = Self(1_048_576);
    pub const MAXIMUM: Self = Self(4_194_304);
    pub fn new(bytes: usize) -> Result<Self, Failure> {
        if !(MAX_HANDSHAKE_BYTES..=Self::MAXIMUM.0).contains(&bytes) {
            return Err(Failure::FrameTooLarge);
        }
        Ok(Self(bytes))
    }
    pub fn limits(self) -> Limits {
        Limits {
            accepted: self.0,
            buffered: self.0 + 1,
            frame: self.0 + 2,
            pending_bytes: self.0 + 2,
            pending_messages: 1,
        }
    }
}

/// Check serialized size without retaining a second copy in the supervisor.
pub(crate) fn validate_command_size(
    value: &impl Serialize,
    budget: CommandBudget,
) -> Result<(), SupervisorError> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.0 {
                return Err(std::io::Error::other("command frame capacity exceeded"));
            }
            self.0 -= bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Count(budget.limits().accepted), value)
        .map_err(|_| SupervisorError::Contract(Failure::FrameTooLarge))
}

pub struct ManagedOwner {
    spec: OwnerSpec,
    pub process_ref: OwnerProcessRef,
    observation: Availability,
    process: OwnedProcess,
    reader: Reader<tokio::io::DuplexStream>,
    writer: Writer<Box<dyn tokio::io::AsyncWrite + Unpin + Send>>,
    diagnostic_drain: Option<tokio::task::JoinHandle<std::io::Result<u64>>>,
    transport_poisoned: bool,
    command_budget: Option<CommandBudget>,
}
impl ManagedOwner {
    pub async fn launch(spec: OwnerSpec) -> Result<Self, SupervisorError> {
        Self::launch_channel(spec, None).await
    }
    pub async fn launch_commands(
        spec: OwnerSpec,
        budget: CommandBudget,
    ) -> Result<Self, SupervisorError> {
        Self::launch_channel(spec, Some(budget)).await
    }
    async fn launch_channel(
        spec: OwnerSpec,
        command_budget: Option<CommandBudget>,
    ) -> Result<Self, SupervisorError> {
        if !spec.executable.is_absolute()
            || spec.args.len() > 128
            || spec.args.iter().map(String::len).sum::<usize>() > 65536
        {
            return Err(SupervisorError::InvalidSpec);
        }
        // Hashing an executable is blocking IO/CPU work. Running it on the
        // current-thread reactor can expire another owner's health exchange
        // while that owner's valid reply is already waiting to be read.
        if executable_digest_async(spec.executable.clone()).await? != spec.executable_identity {
            return Err(SupervisorError::ExecutableMismatch);
        }
        let process_ref = OwnerProcessRef::issue(
            spec.owner_ref.clone(),
            spec.protocol_generation,
            spec.executable_identity,
        )?;
        let mut launch = Launch::new(&spec.executable).args(spec.args.clone());
        for (key, value) in &spec.environment {
            launch = launch.env(key, value);
        }
        let mut process = OwnedProcess::spawn(launch).await?;
        // Validate the actual exec image, not just the selected path. Script or
        // replaced image mismatches fail closed before any handshake/domain use.
        let actual = PathBuf::from(format!(
            "/proc/{}/exe",
            process
                .pid_for_diagnostics()
                .ok_or(SupervisorError::InvalidSpec)?
        ));
        if executable_digest_async(actual).await? != spec.executable_identity {
            process.shutdown(Duration::ZERO).await?;
            return Err(SupervisorError::ExecutableMismatch);
        }
        let connection = Connection::new()?;
        connection.open()?;
        let limits = command_budget.map_or_else(wire_limits, CommandBudget::limits);
        let reader = Reader::new(
            process.take_stdout().ok_or(SupervisorError::InvalidSpec)?,
            wire_limits(),
            connection.clone(),
        )?;
        let input: Box<dyn tokio::io::AsyncWrite + Unpin + Send> =
            Box::new(process.take_stdin().ok_or(SupervisorError::InvalidSpec)?);
        let writer = Writer::new(input, limits, connection, Duration::from_secs(1))?;
        let mut diagnostic = process.take_stderr().ok_or(SupervisorError::InvalidSpec)?;
        // Diagnostics are not canonical results. Drain with a fixed-size IO
        // buffer, without collecting arbitrary child text or blocking framing.
        let diagnostic_drain =
            tokio::spawn(
                async move { tokio::io::copy(&mut diagnostic, &mut tokio::io::sink()).await },
            );
        Ok(Self {
            spec,
            process_ref,
            process,
            reader,
            writer,
            diagnostic_drain: Some(diagnostic_drain),
            transport_poisoned: false,
            command_budget,
            observation: Availability {
                process_alive: true,
                transport_available: false,
                owner_ready: OwnerReady::Starting,
                domain_dispatch_available: false,
            },
        })
    }
    /// Single-flight transport for a caller's closed typed owner contract.
    /// The verifier must check exact incarnation and request correlation before
    /// the channel becomes reusable. No domain operation is synthesized/replayed.
    /// Poison before the first await makes cancellation/timeout fail closed too.
    pub async fn exchange<Q: Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        request: &Q,
        budget: Duration,
        verify: impl FnOnce(&R) -> Result<(), Failure>,
    ) -> Result<R, SupervisorError> {
        if self.transport_poisoned {
            return Err(SupervisorError::TransportPoisoned);
        }
        if self.command_budget.is_none()
            || !self.observation.transport_available
            || budget.is_zero()
            || budget > Duration::from_secs(30)
        {
            return Err(SupervisorError::ControlUnavailable);
        }
        let previous = self.observation.clone();
        self.transport_poisoned = true;
        self.observation.transport_available = false;
        self.observation.domain_dispatch_available = false;
        let result = tokio::time::timeout(budget, async {
            self.writer
                .send(|w| serde_json::to_writer(w, request).map_err(std::io::Error::other))
                .await?;
            let frame = self
                .reader
                .next_frame()
                .await?
                .ok_or(SupervisorError::Transport(
                    crowsi_transport_foundation::Outcome::ConnectionClosed,
                ))?;
            let response: R = serde_json::from_slice(&frame.payload)
                .map_err(|_| SupervisorError::Contract(Failure::InvalidFrame))?;
            verify(&response)?;
            Ok::<R, SupervisorError>(response)
        })
        .await;
        match result {
            Ok(Ok(response)) => {
                self.transport_poisoned = false;
                self.observation = previous;
                Ok(response)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(SupervisorError::Deadline),
        }
    }
    pub async fn handshake(&mut self) -> Result<Handshake, SupervisorError> {
        if self.transport_poisoned {
            return Err(SupervisorError::TransportPoisoned);
        }
        self.reader.decoder = crowsi_transport_foundation::Decoder::new(wire_limits())?;
        self.transport_poisoned = true;
        self.observation.transport_available = false;
        self.observation.domain_dispatch_available = false;
        let request = HandshakeRequest {
            expected: self.process_ref.clone(),
            owner_type: self.spec.owner_type,
        };
        let result = async {
            self.writer
                .send(|w| serde_json::to_writer(w, &request).map_err(std::io::Error::other))
                .await?;
            let frame = self
                .reader
                .next_frame()
                .await?
                .ok_or(SupervisorError::Transport(
                    crowsi_transport_foundation::Outcome::ConnectionClosed,
                ))?;
            Ok::<_, SupervisorError>(Handshake::decode_exact(
                &frame.payload,
                &self.process_ref,
                self.spec.owner_type,
            )?)
        };
        let value = tokio::time::timeout(Duration::from_secs(2), result).await;
        match value {
            Ok(Ok(handshake)) => {
                if let Some(budget) = self.command_budget {
                    self.reader.decoder =
                        crowsi_transport_foundation::Decoder::new(budget.limits())?;
                }
                self.transport_poisoned = false;
                self.observation = handshake.availability.clone();
                Ok(handshake)
            }
            error => {
                // A timed-out exchange may leave a partial frame or late reply.
                // Never turn that reply into a fresh health observation.
                self.transport_poisoned = true;
                self.observation.transport_available = false;
                self.observation.domain_dispatch_available = false;
                self.observation.owner_ready =
                    OwnerReady::Unavailable(UnavailableCause::HandshakeRejected);
                match error {
                    Ok(Err(error)) => Err(error),
                    _ => Err(SupervisorError::Deadline),
                }
            }
        }
    }
    pub fn observation(&mut self) -> Result<Availability, SupervisorError> {
        if !self.process.is_alive()? {
            self.observation.process_lost();
        }
        Ok(self.observation.clone())
    }
    pub fn pid_for_diagnostics(&self) -> Option<u32> {
        self.process.pid_for_diagnostics()
    }
    pub async fn shutdown(&mut self) -> Result<(), SupervisorError> {
        let result = self.process.shutdown(Duration::from_millis(250)).await;
        if let Some(task) = self.diagnostic_drain.take() {
            task.abort();
            let _ = task.await;
        }
        self.observation.process_lost();
        result?;
        Ok(())
    }
    pub async fn restart_physical(&mut self) -> Result<(), SupervisorError> {
        if !self
            .spec
            .owner_type
            .initial_restart_policy()
            .physical_restart_allowed()
        {
            return Err(SupervisorError::RestartRequiresReconciliation);
        }
        self.shutdown().await?;
        let next = Self::launch_channel(self.spec.clone(), self.command_budget).await?;
        *self = next;
        Ok(())
    }
}

impl Drop for ManagedOwner {
    fn drop(&mut self) {
        if let Some(task) = &self.diagnostic_drain {
            task.abort();
        }
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn command_channel_is_bounded_cancel_safe_and_never_automatically_replays() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct ProbeCommand {
            sequence: u64,
            data: String,
            delay_ms: u64,
        }
        let mut owner = ManagedOwner::launch_commands(
            spec("graph/commands", "commands"),
            CommandBudget::STANDARD,
        )
        .await
        .unwrap();
        owner.handshake().await.unwrap();
        let request = ProbeCommand {
            sequence: 1,
            data: "x".repeat(8192),
            delay_ms: 0,
        };
        let response: ProbeCommand = owner
            .exchange(&request, Duration::from_secs(1), |r: &ProbeCommand| {
                if r.sequence == 1 {
                    Ok(())
                } else {
                    Err(Failure::InvalidFrame)
                }
            })
            .await
            .unwrap();
        assert_eq!(request, response);
        let slow = ProbeCommand {
            sequence: 2,
            data: "bounded".into(),
            delay_ms: 100,
        };
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                owner.exchange::<_, ProbeCommand>(&slow, Duration::from_secs(1), |_| Ok(()))
            )
            .await
            .is_err()
        );
        assert!(matches!(
            owner
                .exchange::<_, ProbeCommand>(&request, Duration::from_secs(1), |_| Ok(()))
                .await,
            Err(SupervisorError::TransportPoisoned)
        ));
        let state = owner.observation().unwrap();
        assert!(state.process_alive);
        assert!(!state.transport_available && !state.domain_dispatch_available);
        let previous = owner.process_ref.clone();
        owner.restart_physical().await.unwrap();
        assert_ne!(previous.incarnation, owner.process_ref.incarnation);
        owner.handshake().await.unwrap();
        // Wrong correlation is rejected even when decoding and framing succeed.
        assert!(matches!(
            owner
                .exchange::<_, ProbeCommand>(&request, Duration::from_secs(1), |_| Err(
                    Failure::StaleIncarnation
                ))
                .await,
            Err(SupervisorError::Contract(Failure::StaleIncarnation))
        ));
        assert!(matches!(
            owner.handshake().await,
            Err(SupervisorError::TransportPoisoned)
        ));
        owner.restart_physical().await.unwrap();
        owner.handshake().await.unwrap();
        let oversized = ProbeCommand {
            sequence: 1,
            data: "x".repeat(CommandBudget::STANDARD.limits().accepted),
            delay_ms: 0,
        };
        assert!(matches!(
            owner
                .exchange::<_, ProbeCommand>(&oversized, Duration::from_secs(1), |_| Ok(()))
                .await,
            Err(SupervisorError::Transport(
                crowsi_transport_foundation::Outcome::InputTooLarge
            ))
        ));
        assert!(owner.observation().unwrap().process_alive);
        assert!(matches!(
            owner.handshake().await,
            Err(SupervisorError::TransportPoisoned)
        ));
        owner.shutdown().await.unwrap();
    }
    fn spec(reference: &str, mode: &str) -> OwnerSpec {
        let executable = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/owner_probe")
            .canonicalize()
            .expect("build the owner_probe example before process tests");
        OwnerSpec {
            owner_ref: reference.into(),
            owner_type: if mode == "semantic" {
                OwnerType::Semantic
            } else {
                OwnerType::Graph
            },
            executable_identity: executable_digest(&executable).unwrap(),
            executable,
            protocol_generation: [1; 32],
            args: vec![mode.into()],
            environment: Default::default(),
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_pressure_and_late_reply_cannot_invent_readiness() {
        // On a single-thread reactor, hashing must yield so another owner's
        // already accepted health reply is not starved by a new launch.
        let progressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = progressed.clone();
        let tick = tokio::spawn(async move {
            marker.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        let executable = std::env::current_exe().unwrap();
        let digest = executable_digest_async(executable.clone()).await.unwrap();
        assert!(progressed.load(std::sync::atomic::Ordering::SeqCst));
        tick.await.unwrap();
        assert_eq!(digest, executable_digest(&executable).unwrap());
        let mut isolated = spec("graph/environment", "environment");
        isolated
            .environment
            .insert("HATTER_TEST_OWNER_LAUNCH".into(), "isolated".into());
        let debug = format!("{isolated:?}");
        assert!(!debug.contains("isolated"));
        let mut missing = serde_json::to_value(&isolated).unwrap();
        missing.as_object_mut().unwrap().remove("environment");
        assert!(serde_json::from_value::<OwnerSpec>(missing).is_err());
        let mut owner = ManagedOwner::launch(isolated.clone()).await.unwrap();
        assert_eq!(
            owner.handshake().await.unwrap().availability.owner_ready,
            OwnerReady::Ready
        );
        owner.shutdown().await.unwrap();
        isolated.environment = (0..65).map(|i| (format!("K{i}"), "v".into())).collect();
        assert!(matches!(
            ManagedOwner::launch(isolated).await,
            Err(SupervisorError::Mechanism(
                crowsi_process_adapter::Error::InvalidLaunch
            ))
        ));
        assert!(matches!(
            executable_digest(std::path::Path::new("/dev/null")),
            Err(SupervisorError::InvalidSpec)
        ));
        let mut noisy = ManagedOwner::launch(spec("graph/noisy", "noisy"))
            .await
            .unwrap();
        let mut late = ManagedOwner::launch(spec("graph/late", "late"))
            .await
            .unwrap();
        assert!(
            noisy
                .handshake()
                .await
                .unwrap()
                .availability
                .domain_dispatch_available
        );
        assert!(matches!(
            late.handshake().await,
            Err(SupervisorError::Deadline)
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(matches!(
            late.handshake().await,
            Err(SupervisorError::TransportPoisoned)
        ));
        let state = late.observation().unwrap();
        assert!(!state.transport_available && !state.domain_dispatch_available);
        assert!(noisy.observation().unwrap().process_alive);
        noisy.shutdown().await.unwrap();
        late.shutdown().await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn supervised_commands_outlive_observers_and_remain_bounded_and_incarnation_exact() {
        use crate::supervision::{Control, Protocol, SupervisedOwner};
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct Command {
            sequence: u64,
            data: String,
            delay_ms: u64,
        }
        enum Probe<const LARGE: bool = false> {}
        impl<const LARGE: bool> Protocol for Probe<LARGE> {
            type Request = Command;
            type Response = Command;
            const COMMAND_BUDGET: Option<CommandBudget> = Some(if LARGE {
                CommandBudget::MAXIMUM
            } else {
                CommandBudget::STANDARD
            });
            fn verify(
                request: &Command,
                response: &Command,
                _: &OwnerProcessRef,
            ) -> Result<(), Failure> {
                if request == response {
                    Ok(())
                } else {
                    Err(Failure::InvalidFrame)
                }
            }
        }
        assert!(CommandBudget::new(0).is_err());
        assert!(CommandBudget::new(4_194_305).is_err());
        assert_eq!(
            CommandBudget::new(1_048_576).unwrap(),
            CommandBudget::STANDARD
        );
        // Explicit larger closed protocol only; standard and health limits do
        // not change. Pre-enqueue accounting and restart keep the same budget.
        {
            let large =
                SupervisedOwner::<Probe<true>>::start_protocol(spec("graph/large", "large"))
                    .await
                    .unwrap();
            let initial = large.control(Control::Inspect).await.unwrap();
            let ready = large
                .control(Control::Probe(initial.process.clone()))
                .await
                .unwrap();
            assert!(ready.availability.domain_dispatch_available);
            let request = Command {
                sequence: 1,
                data: "x".repeat(3 * 1_048_576),
                delay_ms: 0,
            };
            let actual = large
                .exchange(
                    initial.process.clone(),
                    Command {
                        sequence: request.sequence,
                        data: request.data.clone(),
                        delay_ms: 0,
                    },
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(actual, request);
            let restarted = large
                .control(Control::Restart(initial.process.clone()))
                .await
                .unwrap();
            assert_ne!(restarted.process.incarnation, initial.process.incarnation);
            let ready = large
                .control(Control::Probe(restarted.process.clone()))
                .await
                .unwrap();
            assert!(ready.availability.domain_dispatch_available);
            assert_eq!(
                large
                    .exchange(
                        restarted.process.clone(),
                        Command {
                            sequence: request.sequence,
                            data: request.data.clone(),
                            delay_ms: 0
                        },
                        Duration::from_secs(5)
                    )
                    .await
                    .unwrap(),
                request
            );
            assert!(matches!(
                large
                    .exchange(
                        restarted.process.clone(),
                        Command {
                            sequence: 2,
                            data: "x".repeat(4_194_304),
                            delay_ms: 0
                        },
                        Duration::from_secs(1)
                    )
                    .await,
                Err(SupervisorError::Contract(Failure::FrameTooLarge))
            ));
            let after = large.control(Control::Inspect).await.unwrap();
            assert_eq!(after.process, restarted.process);
            assert!(after.availability.transport_available);
            large.close().await.unwrap();
        }
        let owner = SupervisedOwner::<Probe>::start_protocol(spec("graph/commands", "commands"))
            .await
            .unwrap();
        let initial = owner.control(Control::Inspect).await.unwrap();
        let ready = owner
            .control(Control::Probe(initial.process.clone()))
            .await
            .unwrap();
        assert!(ready.availability.domain_dispatch_available);
        let request = |sequence, delay_ms| Command {
            sequence,
            data: "bounded".into(),
            delay_ms,
        };
        // This timeout cancels only the observer. The actor must consume the late
        // response itself before health or another command uses the same stream.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(5),
                owner.exchange(
                    initial.process.clone(),
                    request(1, 100),
                    Duration::from_secs(1)
                )
            )
            .await
            .is_err()
        );
        let settled = owner.control(Control::Inspect).await.unwrap();
        assert!(settled.availability.transport_available);
        assert_eq!(settled.process, initial.process);
        assert_eq!(
            owner
                .exchange(
                    initial.process.clone(),
                    request(2, 0),
                    Duration::from_secs(1)
                )
                .await
                .unwrap(),
            request(2, 0)
        );
        assert!(matches!(
            owner
                .exchange(
                    initial.process.clone(),
                    Command {
                        sequence: 3,
                        data: "x".repeat(CommandBudget::STANDARD.limits().accepted),
                        delay_ms: 0,
                    },
                    Duration::from_secs(1)
                )
                .await,
            Err(SupervisorError::Contract(Failure::FrameTooLarge))
        ));
        assert!(
            owner
                .control(Control::Inspect)
                .await
                .unwrap()
                .availability
                .transport_available
        );
        // A physical exchange timeout has a different meaning and poisons the
        // stream without pretending that the domain operation was cancelled.
        assert!(matches!(
            owner
                .exchange(
                    initial.process.clone(),
                    request(3, 100),
                    Duration::from_millis(5)
                )
                .await,
            Err(SupervisorError::Deadline)
        ));
        assert!(
            !owner
                .control(Control::Inspect)
                .await
                .unwrap()
                .availability
                .transport_available
        );
        let replaced = owner
            .control(Control::Restart(initial.process.clone()))
            .await
            .unwrap();
        assert_ne!(replaced.process.incarnation, initial.process.incarnation);
        owner
            .control(Control::Probe(replaced.process.clone()))
            .await
            .unwrap();
        assert!(matches!(
            owner
                .exchange(initial.process, request(4, 0), Duration::from_secs(1))
                .await,
            Err(SupervisorError::Contract(Failure::StaleIncarnation))
        ));
        assert_eq!(
            owner
                .exchange(replaced.process, request(1, 0), Duration::from_secs(1))
                .await
                .unwrap(),
            request(1, 0)
        );
        owner.close().await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn bounded_background_health_restarts_only_dead_safe_owner_and_stop_is_final() {
        use crate::supervision::{Control, SupervisedOwner};
        let graph = SupervisedOwner::start(spec("graph/exit", "exit"))
            .await
            .unwrap();
        let first = graph.control(Control::Inspect).await.unwrap();
        let recovering = SupervisedOwner::start(spec("semantic/recovering", "semantic"))
            .await
            .unwrap();
        let semantic = recovering.control(Control::Inspect).await.unwrap();
        let final_state = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let state = graph.control(Control::Inspect).await.unwrap();
                if state.automatic_restarts == 3 && !state.availability.process_alive {
                    break state;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert_ne!(final_state.process.incarnation, first.process.incarnation);
        assert!(!final_state.availability.domain_dispatch_available);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            graph.control(Control::Inspect).await.unwrap().process,
            final_state.process
        );
        let current = recovering.control(Control::Inspect).await.unwrap();
        assert_eq!(current.process, semantic.process);
        assert_eq!(current.automatic_restarts, 0);
        assert_eq!(current.availability.owner_ready, OwnerReady::Recovering);
        let live = SupervisedOwner::start(spec("graph/stop", "ready"))
            .await
            .unwrap();
        let original = live.control(Control::Inspect).await.unwrap();
        live.control(Control::Stop(original.process.clone()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let stopped = live.control(Control::Inspect).await.unwrap();
        assert_eq!(stopped.process, original.process);
        assert!(!stopped.availability.process_alive);
        assert_eq!(stopped.automatic_restarts, 0);
        live.close().await.unwrap();
        recovering.close().await.unwrap();
        graph.close().await.unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn physical_peers_exact_handshake_isolation_restart_and_no_replay() {
        let mut graph = ManagedOwner::launch(spec("graph/control", "ready"))
            .await
            .unwrap();
        let mut semantic = ManagedOwner::launch(spec("semantic/main", "semantic"))
            .await
            .unwrap();
        let g1 = graph.process_ref.clone();
        let s1 = semantic.process_ref.clone();
        let initial = graph.observation().unwrap();
        assert!(initial.process_alive);
        assert!(!initial.transport_available);
        assert!(!initial.domain_dispatch_available);
        assert_eq!(
            graph.handshake().await.unwrap().availability.owner_ready,
            OwnerReady::Ready
        );
        let state = semantic.handshake().await.unwrap().availability;
        assert!(state.process_alive && state.transport_available);
        assert_eq!(state.owner_ready, OwnerReady::Recovering);
        assert!(!state.domain_dispatch_available);
        assert!(matches!(
            semantic.restart_physical().await,
            Err(SupervisorError::RestartRequiresReconciliation)
        ));
        graph.process.kill().unwrap();
        graph.process.wait().await.unwrap();
        assert!(!graph.observation().unwrap().process_alive);
        assert!(semantic.observation().unwrap().process_alive);
        graph.restart_physical().await.unwrap();
        let g2 = graph.process_ref.clone();
        assert_ne!(g1.incarnation, g2.incarnation);
        assert_eq!(g1.owner_ref, g2.owner_ref);
        assert_eq!(semantic.process_ref, s1);
        // Physical replacement alone never sets transport, owner or domain Ready.
        assert!(!graph.observation().unwrap().domain_dispatch_available);
        assert_eq!(
            graph.process_ref.verify(&g1),
            Err(Failure::StaleIncarnation)
        );
        graph.handshake().await.unwrap();
        semantic.handshake().await.unwrap();
        graph.shutdown().await.unwrap();
        semantic.shutdown().await.unwrap();
        let mut corrupt = ManagedOwner::launch(spec("graph/broken", "corrupt"))
            .await
            .unwrap();
        let state = corrupt.handshake().await.unwrap().availability;
        assert!(state.process_alive && state.transport_available);
        assert_eq!(
            state.owner_ready,
            OwnerReady::Unavailable(UnavailableCause::Corrupt)
        );
        assert!(!state.domain_dispatch_available);
        corrupt.shutdown().await.unwrap();
    }
}
