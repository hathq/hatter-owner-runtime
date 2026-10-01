//! Compound process-boundary proof. Peers are explicit test fixtures, not domain owners.
#![cfg(target_os = "linux")]
use crowsi_process_adapter::{Launch, OwnedProcess};
use crowsi_transport_foundation::{
    Connection, Limits,
    io::{Reader, Writer},
};
use hatter_owner_contracts::{OwnerProcessRef, OwnerType};
use hatter_owner_runtime::supervisor::{OwnerSpec, executable_digest};
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};

fn limits() -> Limits {
    Limits {
        accepted: 65536,
        buffered: 65537,
        frame: 65538,
        pending_bytes: 131076,
        pending_messages: 2,
    }
}
async fn request(
    reader: &mut Reader<tokio::io::DuplexStream>,
    writer: &Writer<tokio::io::DuplexStream>,
    id: u64,
    command: Value,
) -> Value {
    writer
        .send(|w| {
            serde_json::to_writer(w, &json!({"id":id,"command":command}))
                .map_err(std::io::Error::other)
        })
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(8), reader.next_frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let value: Value = serde_json::from_slice(&frame.payload).unwrap();
    assert_eq!(value["id"], id);
    value
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn independent_supervisor_exact_control_restart_and_eof_cleanup() {
    let token = OwnerProcessRef::issue("test".into(), [1; 32], [2; 32]).unwrap();
    let dir =
        Directory(std::env::temp_dir().join(format!("hatter-supervisor-{:x?}", token.incarnation)));
    std::fs::create_dir(&dir.0).unwrap();
    let built = PathBuf::from(env!("CARGO_BIN_EXE_hatter-supervisor"));
    // Test-only injection runs exactly the registry-installed executable; no
    // production launcher or source fallback is selected by this variable.
    let exe = std::env::var_os("HATTER_TEST_SUPERVISOR_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| built.clone());
    let peer = built
        .parent()
        .unwrap()
        .join("examples/owner_probe")
        .canonicalize()
        .unwrap();
    let spec = |owner: &str, mode: &str, kind| OwnerSpec {
        owner_ref: owner.into(),
        owner_type: kind,
        executable: peer.clone(),
        executable_identity: executable_digest(&peer).unwrap(),
        protocol_generation: [1; 32],
        args: vec![mode.into()],
        environment: Default::default(),
    };
    let specs = dir.0.join("owners.json");
    std::fs::write(
        &specs,
        serde_json::to_vec(&vec![
            spec("graph/control", "ready", OwnerType::Graph),
            spec("semantic", "semantic", OwnerType::Semantic),
        ])
        .unwrap(),
    )
    .unwrap();
    let mut supervisor = OwnedProcess::spawn(Launch::new(&exe).args([specs.as_os_str()]))
        .await
        .unwrap();
    let pid = supervisor.pid_for_diagnostics().unwrap();
    assert_eq!(
        executable_digest(&PathBuf::from(format!("/proc/{pid}/exe"))).unwrap(),
        executable_digest(&exe).unwrap(),
        "the actual process image must be the selected installed executable"
    );
    println!("supervisor executable: {}", exe.display());
    let connection = Connection::new().unwrap();
    connection.open().unwrap();
    let mut reader = Reader::new(
        supervisor.take_stdout().unwrap(),
        limits(),
        connection.clone(),
    )
    .unwrap();
    let writer = Writer::new(
        supervisor.take_stdin().unwrap(),
        limits(),
        connection,
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(
        request(
            &mut reader,
            &writer,
            1,
            json!({"Start":{"owner_ref":"unknown"}})
        )
        .await
        .get("error")
        .is_some()
    );
    let g1 = request(
        &mut reader,
        &writer,
        2,
        json!({"Start":{"owner_ref":"graph/control"}}),
    )
    .await;
    assert_eq!(g1["result"]["availability"]["owner_ready"], "Starting");
    let g1 = g1["result"]["process"].clone();
    let ready = request(&mut reader, &writer, 3, json!({"Probe":{"process":g1}})).await;
    assert_eq!(
        ready["result"]["availability"]["domain_dispatch_available"],
        true
    );
    let s = request(
        &mut reader,
        &writer,
        4,
        json!({"Start":{"owner_ref":"semantic"}}),
    )
    .await["result"]["process"]
        .clone();
    assert_eq!(
        request(&mut reader, &writer, 5, json!({"Probe":{"process":s}})).await["result"]["availability"]
            ["owner_ready"],
        "Recovering"
    );
    assert_eq!(
        request(&mut reader, &writer, 6, json!({"Restart":{"process":s}})).await["error"]["code"],
        "RestartRequiresReconciliation"
    );
    let g2 = request(&mut reader, &writer, 7, json!({"Restart":{"process":g1}})).await;
    assert_ne!(g2["result"]["process"]["incarnation"], g1["incarnation"]);
    assert_eq!(
        g2["result"]["availability"]["domain_dispatch_available"],
        false
    );
    assert!(
        request(&mut reader, &writer, 8, json!({"Stop":{"process":g1}}))
            .await
            .get("error")
            .is_some()
    );
    assert_eq!(
        request(
            &mut reader,
            &writer,
            9,
            json!({"Inspect":{"owner_ref":"semantic"}})
        )
        .await["result"]["process"],
        s
    );
    let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).unwrap();
    let children: Vec<u32> = children
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert!(
        !children.is_empty(),
        "test must observe real child processes"
    );
    drop(writer); // EOF is orderly supervisor shutdown, not retained Running state.
    let exit = tokio::time::timeout(Duration::from_secs(10), supervisor.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exit.code(), Some(0));
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    for child in children {
        assert!(
            !PathBuf::from(format!("/proc/{child}")).exists(),
            "child must be reaped"
        );
    }
    // Extra command fields must not be silently absorbed as a compatibility path.
    let mut rejected = OwnedProcess::spawn(Launch::new(&exe).args([specs.as_os_str()]))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut input = rejected.take_stdin().unwrap();
    input.write_all(b"{\"id\":1,\"command\":{\"Start\":{\"owner_ref\":\"graph/control\",\"domain_request\":\"not allowed\"}}}\n").await.unwrap();
    drop(input);
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(3),
        rejected.take_stdout().unwrap().read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        bytes.is_empty(),
        "invalid control must not start and acknowledge an owner"
    );
    assert_ne!(rejected.wait().await.unwrap().code(), Some(0));
}
