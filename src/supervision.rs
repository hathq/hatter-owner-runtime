//! Hatter 2026: one bounded physical owner actor and typed single-flight transport.
//! Commands are transient caller-owned messages, never Work or persistent authority.
use crate::supervisor::{CommandBudget, ManagedOwner, OwnerSpec, SupervisorError};
use hatter_owner_contracts::{Availability, Failure, OwnerProcessRef};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};

#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub process: OwnerProcessRef,
    pub availability: Availability,
    pub automatic_restarts: u8,
}
pub enum Control {
    Inspect,
    Probe(OwnerProcessRef),
    Restart(OwnerProcessRef),
    Stop(OwnerProcessRef),
}
type Reply = Result<Observation, SupervisorError>;

/// A closed owner protocol supplies its codec/correlation check, not execution
/// policy. No closure, callback, method name or repository is sent across IPC.
pub trait Protocol: Send + 'static {
    type Request: Serialize + Send + Sync + 'static;
    type Response: DeserializeOwned + Send + 'static;
    const COMMAND_BUDGET: Option<CommandBudget>;
    fn verify(
        request: &Self::Request,
        response: &Self::Response,
        process: &OwnerProcessRef,
    ) -> Result<(), Failure>;
}

/// Health-only supervised processes cannot receive domain messages.
pub enum HealthOnly {}
#[derive(Serialize, Deserialize)]
pub enum NoCommand {}
impl Protocol for HealthOnly {
    type Request = NoCommand;
    type Response = NoCommand;
    const COMMAND_BUDGET: Option<CommandBudget> = None;
    fn verify(_: &NoCommand, response: &NoCommand, _: &OwnerProcessRef) -> Result<(), Failure> {
        match *response {}
    }
}

enum Message<P: Protocol> {
    Control(Control, oneshot::Sender<Reply>),
    Exchange {
        process: OwnerProcessRef,
        request: P::Request,
        budget: Duration,
        reply: oneshot::Sender<Result<P::Response, SupervisorError>>,
    },
}
/// One actor owns one process handle. Queue capacity and restart count are hard bounded.
pub struct SupervisedOwner<P: Protocol = HealthOnly> {
    sender: mpsc::Sender<Message<P>>,
    task: tokio::task::JoinHandle<Result<(), SupervisorError>>,
}
impl SupervisedOwner<HealthOnly> {
    pub async fn start(spec: OwnerSpec) -> Result<Self, SupervisorError> {
        Self::start_protocol(spec).await
    }
}
impl<P: Protocol> SupervisedOwner<P> {
    pub async fn start_protocol(spec: OwnerSpec) -> Result<Self, SupervisorError> {
        let allow_restart = spec
            .owner_type
            .initial_restart_policy()
            .physical_restart_allowed();
        let owner = if let Some(budget) = P::COMMAND_BUDGET {
            ManagedOwner::launch_commands(spec, budget).await?
        } else {
            ManagedOwner::launch(spec).await?
        };
        let (sender, receiver) = mpsc::channel(4);
        let task = tokio::spawn(run(owner, receiver, allow_restart));
        Ok(Self { sender, task })
    }
    pub async fn control(&self, command: Control) -> Reply {
        let (tx, rx) = oneshot::channel();
        self.sender
            .try_send(Message::Control(command, tx))
            .map_err(|_| SupervisorError::ControlUnavailable)?;
        rx.await.map_err(|_| SupervisorError::ControlUnavailable)?
    }
    /// Once queued, observer cancellation cannot abort the owner's exchange.
    /// An owner timeout poisons that stream; physical restart never replays it.
    pub async fn exchange(
        &self,
        process: OwnerProcessRef,
        request: P::Request,
        budget: Duration,
    ) -> Result<P::Response, SupervisorError> {
        let command_budget = P::COMMAND_BUDGET.ok_or(SupervisorError::ControlUnavailable)?;
        if budget.is_zero() || budget > Duration::from_secs(30) {
            return Err(SupervisorError::ControlUnavailable);
        }
        // Bound before enqueue as well as at Crowsi serialization. At most four
        // admitted messages plus the in-flight message consume this actor queue.
        crate::supervisor::validate_command_size(&request, command_budget)?;
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Message::Exchange {
                process,
                request,
                budget,
                reply,
            })
            .map_err(|_| SupervisorError::ControlUnavailable)?;
        receive
            .await
            .map_err(|_| SupervisorError::ControlUnavailable)?
    }
    pub async fn close(mut self) -> Result<(), SupervisorError> {
        let (replacement, _) = mpsc::channel(1);
        drop(std::mem::replace(&mut self.sender, replacement));
        (&mut self.task)
            .await
            .map_err(|_| SupervisorError::ControlUnavailable)?
    }
}
impl<P: Protocol> Drop for SupervisedOwner<P> {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn run<P: Protocol>(
    mut owner: ManagedOwner,
    mut input: mpsc::Receiver<Message<P>>,
    allow_restart: bool,
) -> Result<(), SupervisorError> {
    let mut clock = tokio::time::interval(Duration::from_millis(100));
    clock.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut probe_due = Instant::now() + Duration::from_secs(1);
    let mut restart_due = None;
    let mut attempts = 0u8;
    let mut stopped = false;
    loop {
        tokio::select! {
            message=input.recv()=>{
                let Some(message)=message else {break};
                let (command, reply) = match message {
                    Message::Control(command, reply) => (command, reply),
                    Message::Exchange { process, request, budget, reply } => {
                        let result = async {
                            owner.process_ref.verify(&process)?;
                            if stopped { return Err(SupervisorError::ControlUnavailable); }
                            owner.exchange(&request, budget, |response| P::verify(&request, response, &process)).await
                        }.await;
                        // Lost observer is not a rollback or a reason to dispatch again.
                        let _ = reply.send(result);
                        probe_due = Instant::now() + Duration::from_secs(1);
                        continue;
                    }
                };
                let result=async {
                    match command {
                        Control::Inspect=>{},
                        Control::Probe(reference)=>{owner.process_ref.verify(&reference)?;owner.handshake().await?;},
                        Control::Restart(reference)=>{owner.process_ref.verify(&reference)?;owner.restart_physical().await?;stopped=false;restart_due=None;},
                        Control::Stop(reference)=>{owner.process_ref.verify(&reference)?;stopped=true;restart_due=None;owner.shutdown().await?;},
                    }
                    Ok(Observation{process:owner.process_ref.clone(),availability:owner.observation()?,automatic_restarts:attempts})
                }.await;
                let _=reply.send(result);
            },
            _=clock.tick()=>{
                if stopped {continue}
                let Ok(state)=owner.observation() else {continue};
                let now=Instant::now();
                if !state.process_alive {
                    if allow_restart && attempts<3 {
                        let due=restart_due.get_or_insert_with(||now+Duration::from_millis(100u64<<attempts));
                        if now>=*due {
                            attempts+=1;restart_due=None;
                            // Mechanism gets a fresh incarnation only. No last request exists here.
                            let _=owner.restart_physical().await;
                            probe_due=Instant::now()+Duration::from_secs(1);
                        }
                    } else {
                        // No restart does not mean retaining dead process handles,
                        // pumps or descendants until the supervisor itself exits.
                        stopped=true;
                        let _=owner.shutdown().await;
                    }
                } else if now>=probe_due {
                    // Typed Corrupt/Missing/Recovering never cause a restart loop.
                    // A poisoned stream cannot reuse a late response as health.
                    let _=owner.handshake().await;
                    probe_due=Instant::now()+Duration::from_secs(1);
                }
            }
        }
    }
    owner.shutdown().await
}
