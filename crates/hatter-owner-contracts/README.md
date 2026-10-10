# hatter-owner-contracts

Identify an owner process consistently across startup, observation and restart.

## What you can do

- Validate owner reference, incarnation, protocol generation and executable identity.
- Distinguish process life, transport, readiness and dispatch state.

## Current scope

PID alone is not process identity. These contracts do not start processes or authorize replay of a domain command.

The reusable Rust packages are distributed independently through crates.io. Development uses a versioned workspace path for the shared contracts; the published package resolves the same version from the public registry.

## Getting started

Install Rust 1.97.0 or newer and make the declared dependencies available. No private registry or sibling repository checkout is required. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
