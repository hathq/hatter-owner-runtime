//! Hatter 2026: independent physical supervisor, configured owners only.
use crowsi_transport_foundation::{
    Connection, Limits,
    io::{Reader, Writer},
};
use hatter_owner_contracts::OwnerProcessRef;
use hatter_owner_runtime::supervision::{Control, Observation, SupervisedOwner};
use hatter_owner_runtime::supervisor::{OwnerSpec, SupervisorError};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Read, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    command: Command,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum Command {
    Start { owner_ref: String },
    Inspect { owner_ref: String },
    Probe { process: OwnerProcessRef },
    Restart { process: OwnerProcessRef },
    Stop { process: OwnerProcessRef },
}
fn limits() -> Limits {
    Limits {
        accepted: 65536,
        buffered: 65537,
        frame: 65538,
        pending_bytes: 131076,
        pending_messages: 2,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 2 {
        return Err("usage: hatter-supervisor REVIEWED_OWNER_SPEC_FILE".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[1])?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("OwnerSpecTooLarge".into());
    }
    let declared: Vec<OwnerSpec> = serde_json::from_slice(&bytes)?;
    if declared.len() > 16 {
        return Err("OwnerLimit".into());
    }
    let mut specs = BTreeMap::new();
    for spec in declared {
        if specs.insert(spec.owner_ref.clone(), spec).is_some() {
            return Err("DuplicateOwner".into());
        }
    }
    let mut owners = BTreeMap::<String, SupervisedOwner>::new();
    let connection = Connection::new().map_err(|_| "ConnectionFailed")?;
    connection.open().map_err(|_| "ConnectionFailed")?;
    let mut reader = Reader::new(tokio::io::stdin(), limits(), connection.clone())
        .map_err(|_| "ConnectionFailed")?;
    let writer = Writer::new(
        tokio::io::stdout(),
        limits(),
        connection,
        Duration::from_secs(2),
    )
    .map_err(|_| "ConnectionFailed")?;
    let result = async {
        while let Some(frame) = reader
            .next_frame()
            .await
            .map_err(|_| "InvalidControlFrame")?
        {
            let request: Request = serde_json::from_slice(&frame.payload)?;
            let id = request.id;
            let reply = execute(request.command, &specs, &mut owners).await;
            let value = match reply {
                Ok(value) => serde_json::json!({"id":id,"result":value}),
                Err(error) => serde_json::json!({"id":id,"error":{"code":error.to_string()}}),
            };
            writer
                .send(|w| serde_json::to_writer(w, &value).map_err(std::io::Error::other))
                .await
                .map_err(|_| "ControlOutputUnavailable")?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    // Only owned handles are stopped. No persisted PID adoption or domain replay.
    let mut cleanup_error = None;
    for owner in owners.into_values() {
        if let Err(error) = owner.close().await {
            cleanup_error = Some(error)
        }
    }
    result?;
    if let Some(error) = cleanup_error {
        return Err(error.into());
    }
    Ok(())
}
async fn execute(
    command: Command,
    specs: &BTreeMap<String, OwnerSpec>,
    owners: &mut BTreeMap<String, SupervisedOwner>,
) -> Result<Observation, SupervisorError> {
    let reference = match &command {
        Command::Start { owner_ref } | Command::Inspect { owner_ref } => owner_ref,
        Command::Probe { process } | Command::Restart { process } | Command::Stop { process } => {
            &process.owner_ref
        }
    }
    .clone();
    if let Command::Start { .. } = &command {
        if owners.contains_key(&reference) {
            return Err(SupervisorError::InvalidSpec);
        }
        let spec = specs
            .get(&reference)
            .ok_or(SupervisorError::InvalidSpec)?
            .clone();
        owners.insert(reference.clone(), SupervisedOwner::start(spec).await?);
    }
    let owner = owners
        .get_mut(&reference)
        .ok_or(SupervisorError::InvalidSpec)?;
    owner
        .control(match command {
            Command::Probe { process } => Control::Probe(process),
            Command::Restart { process } => Control::Restart(process),
            Command::Stop { process } => Control::Stop(process),
            _ => Control::Inspect,
        })
        .await
}
