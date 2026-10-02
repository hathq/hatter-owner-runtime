# hatter-owner-runtime

Start and supervise an explicitly reviewed set of Linux owner processes.

## What you can do

- Pin executable identity and launch configuration.
- Probe, stop and apply declared restart policy.

## Current scope

The caller owns the allowed environment and owner list. Restart creates a new incarnation and does not retry a domain request.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97.0 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Examples](examples) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
