# Using hatter-owner-runtime

Start and supervise an explicitly reviewed set of Linux owner processes.

## Before you start

The caller owns the allowed environment and owner list. Restart creates a new incarnation and does not retry a domain request.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Pin executable identity and launch configuration.
- Probe, stop and apply declared restart policy.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
