# hatter-owner-runtime interface reference

Use the [usage guide](getting-started.md) for the first steps. This reference preserves the current interface details and operational limits. Run command examples from the repository root, after preparing the exact declared dependencies and registered configuration.

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
