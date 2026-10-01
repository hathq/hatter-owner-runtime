//! Hatter downstream 2026: test-only Crowsi peer, NOT a canonical domain owner.
use crowsi_transport_foundation::{
    Connection,
    io::{Reader, Writer},
};
use hatter_owner_contracts::{
    Availability, Handshake, HandshakeRequest, OwnerReady, OwnerType, UnavailableCause,
};
use hatter_owner_runtime::supervisor::{CommandBudget, executable_digest, wire_limits};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).ok_or("test mode required")?;
    if mode == "environment"
        && (std::env::var("HATTER_TEST_OWNER_LAUNCH").as_deref() != Ok("isolated")
            || std::env::var_os("HOME").is_some())
    {
        return Err("launch environment mismatch".into());
    }
    let kind = if mode == "semantic" {
        OwnerType::Semantic
    } else {
        OwnerType::Graph
    };
    let state = match mode.as_str() {
        "semantic" => OwnerReady::Recovering,
        "corrupt" => OwnerReady::Unavailable(UnavailableCause::Corrupt),
        "ready" | "noisy" | "late" | "exit" | "commands" | "large" | "environment" => {
            OwnerReady::Ready
        }
        _ => return Err("invalid test mode".into()),
    };
    let digest = executable_digest(&std::env::current_exe()?)?;
    let c = Connection::new()?;
    c.open()?;
    let limits = match mode.as_str() {
        "commands" => CommandBudget::STANDARD.limits(),
        "large" => CommandBudget::MAXIMUM.limits(),
        _ => wire_limits(),
    };
    let mut reader = Reader::new(tokio::io::stdin(), limits, c.clone())?;
    let writer = Writer::new(tokio::io::stdout(), limits, c, Duration::from_secs(1))?;
    let mut assigned = None;
    while let Some(frame) = reader.next_frame().await? {
        if matches!(mode.as_str(), "commands" | "large")
            && assigned.is_some()
            && let Ok(command) = serde_json::from_slice::<ProbeCommand>(&frame.payload)
        {
            if command.delay_ms > 100 {
                return Err("unbounded test delay".into());
            }
            tokio::time::sleep(Duration::from_millis(command.delay_ms)).await;
            writer
                .send(|w| serde_json::to_writer(w, &command).map_err(std::io::Error::other))
                .await?;
            continue;
        }
        let request: HandshakeRequest = serde_json::from_slice(&frame.payload)?;
        if mode == "noisy" {
            use tokio::io::AsyncWriteExt;
            tokio::io::stderr().write_all(&vec![b'x'; 200000]).await?;
        }
        if mode == "late" {
            tokio::time::sleep(Duration::from_millis(2200)).await;
        }
        request.expected.validate()?;
        if request.owner_type != kind
            || request.expected.executable_identity != digest
            || request.expected.protocol_generation != [1; 32]
        {
            return Err("wrong test binding".into());
        }
        if let Some(original) = &assigned {
            request.expected.verify(original)?;
        } else {
            assigned = Some(request.expected.clone());
        }
        let response = Handshake {
            process: request.expected,
            owner_type: kind,
            availability: Availability {
                process_alive: true,
                transport_available: true,
                owner_ready: state,
                domain_dispatch_available: state == OwnerReady::Ready,
            },
        };
        writer
            .send(|w| serde_json::to_writer(w, &response).map_err(std::io::Error::other))
            .await?;
        if mode == "exit" {
            return Ok(());
        }
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeCommand {
    sequence: u64,
    data: String,
    delay_ms: u64,
}
