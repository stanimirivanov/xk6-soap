# ADR-0004 · Use explicit leaf certificate pins for SOAP message trust

**Status** — Accepted

## Context

The k6 script configures HTTP and TLS. SOAP signature verification needs
its own policy for deciding which peer can authenticate the response,
including when that peer supplies a certificate or identifier in the message.

## Decision

Require explicitly configured trust pins for inbound signature verification.
A pin identifies the full leaf certificate by its exact DER encoding. A
certificate carried in a message or located by its key identifier must
resolve to one configured pin. Signing, encryption recipient and decryption
material are supplied through separate roles. Any future support for
chain-based message trust requires a separate decision.

## Why

Pinning makes peer authorization explicit and independent of the TLS
endpoint and system roots. Trusting message-supplied certificates or a
broader chain would change which identities can authenticate a SOAP response.
Pinning requires scripts to update their trust lists during rotation.
Overlapping pins allow a transition while both are valid and the message
identifies a unique pin. See the [receive contract](../receive.md) and
[validity scope decision](0005-operation-scoped-key-validity.md).
