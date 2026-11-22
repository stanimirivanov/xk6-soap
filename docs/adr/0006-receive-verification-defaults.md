# ADR-0006 · Default receive verification from outbound signing

**Status** — Accepted

## Context

A single Client prepares outbound requests and accepts inbound responses.
A signed request often calls for an authenticated and fresh reply.
Some peers use asymmetric profiles, for example a client that sends
unsigned requests but requires signed responses.

## Decision

When `verify.signature` is omitted, default it to whether outbound
signing is configured. When `verify.timestamp` is omitted, default it to
the resulting receive signature setting. Keep explicit overrides subject
to policy validation, including the requirement that freshness checks
use signature verification. Show explicit settings in examples where
the two directions have different requirements.

Receive signature and digest allow-lists have independent defaults.
An encrypted receive profile still requires an explicit receive order.
See the [security policy reference](../security-policy.md).

## Why

These defaults make a signed request with an authenticated, fresh reply
easy to configure. Requiring explicit receive settings in every script
would make each direction visible but would change the behavior of existing
signed clients. The shorthand couples omitted settings across directions,
so asymmetric exchanges benefit from explicit receive policy.
