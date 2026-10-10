# Using hatter-owner-contracts

Identify an owner process consistently across startup, observation and restart.

## Before you start

PID alone is not process identity. These contracts do not start processes or authorize replay of a domain command.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Validate owner reference, incarnation, protocol generation and executable identity.
- Distinguish process life, transport, readiness and dispatch state.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
