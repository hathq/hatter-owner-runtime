# Hatter owner runtime

<!-- Hatter downstream 2026: command transport supplements the accepted supervisor. -->

Version 0.10.0. Linux-only physical supervision policy. The standalone
`hatter-supervisor REVIEWED_OWNER_SPEC_FILE` binary consumes bounded Crowsi
frames on stdin/stdout. It does not open canonical stores or retain requests.

The reviewed JSON file is an array (at most 16) of `OwnerSpec`: stable owner
reference, owner type, absolute executable path, exact SHA-256 executable
identity, exact 32-byte protocol generation, bounded argument list, and explicit
`environment` map (required even when empty). Crowsi clears inherited variables
and enforces its existing 64-variable/64KiB total launch limit. The product root
selects environment policy; this generic layer neither discovers Hatter paths
nor manufactures routes or credentials. Debug output omits argument/environment
values. Only
listed executables may start; the actual Linux exec image is checked too.

Commands have `{ "id": number, "command": { "Start": { "owner_ref": "..." } } }`
shape. Inspect uses the owner reference. Probe, Restart and Stop require the
full exact `OwnerProcessRef` returned by Start. Restart creates a new random
incarnation, never retries a domain request, and is initially permitted only
for Graph and stateless projection owners. Evidence policy is deny-by-default.

The pure `hatter-owner-contracts` package owns handshake/state wire types.
The Crowsi adapter owns processkit handles and physical shutdown. This package
owns policy, bounded probes and volatile observations. No Graph, semantic,
Work, Evidence, installer, result or health database exists here.

`ManagedOwner::launch_commands` requires an explicit `CommandBudget` after
the original 4KiB exact handshake. The compiled `Protocol::COMMAND_BUDGET` is
`None` for health-only peers, not an ambient default or caller-selected setting.
`STANDARD` preserves 1MiB; a protocol may declare at most 4MiB (`MAXIMUM`). Custom
budgets are validated within 4KiB–4MiB. Serialization-before-enqueue, both Crowsi
directions and physical restart use the same budget. The queue remains four
messages plus one in flight: at most five times the selected encoded-message
capacity, not an allocation/RSS guarantee for arbitrary decoded domain types.
Domain-specific document/count limits remain required before preparation.

`exchange` transports caller-defined closed
types, requires verification of response identity/correlation and has one
in-flight exchange by exclusive borrowing. It supplies no generic method/JSON
dispatcher. Cancellation, deadline, malformed reply or failed verification
poisons reuse before any await can be abandoned; late replies cannot become
fresh success. Handshakes are cancellation-safe too. Observer timeout never
restarts, cancels or resends a domain operation. A physical restart retains the
selected transport bound but replaces the exact process incarnation.

`SupervisedOwner<P>::start_protocol` attaches a closed typed transport codec to
the same actor that owns health and shutdown. There is no second task owning the
process stream. At most four queued control/command messages plus one in flight
are allowed; commands are measured without a retained serialization copy before
enqueue and are bounded again by Crowsi. A caller dropping its reply receiver
does not cancel the accepted exchange. The actor consumes and validates the
response before processing the next message. An actual owner-exchange deadline
still poisons the stream and requires explicit reconciliation, never a resend.
The protocol verifier is local compiled code, never a callback serialized over
the wire. Health-only owners use an uninhabited request type, not a generic RPC.

## Scope of current evidence

The `owner_probe` example is a test peer, not an implementation of either
canonical Graph or Semantic owner. Passing it does not demonstrate product
Management isolation or close the retained corrupt-owner regression. Existing
product callers have not yet been switched to this supervisor. Each owner has
one health actor (four queued control messages), one-second readiness probes
with a two-second deadline and at most three automatic physical restarts.
Backoff is 100/200/400ms; only a physically dead safe/stateless owner is eligible.
Corrupt/Missing/Recovering does not cause a restart loop. Explicit Stop disables
restart. Queue contents, restart budgets and health observations are volatile.

After building `--example owner_probe --bin hatter-supervisor`, run scoped
`cargo test --offline --locked` and `cargo clippy --all-targets -- -D warnings`
with the reviewed immutable ecosystem registry config and shared target.
