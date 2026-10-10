# hatter-owner-runtime

Start and supervise an explicitly reviewed set of Linux owner processes.

## What you can do

- Pin executable identity and launch configuration.
- Probe, stop and apply declared restart policy.

## Current scope

The caller owns the allowed environment and owner list. Restart creates a new incarnation and does not retry a domain request.

The reusable Rust packages are distributed independently through crates.io. Development uses a versioned workspace path for the shared contracts; the published package resolves the same version from the public registry.

## Getting started

Install Rust 1.97.0 or newer and make the declared dependencies available. No private registry or sibling repository checkout is required. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
