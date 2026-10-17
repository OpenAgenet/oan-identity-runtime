<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# OAN Identity Runtime

An edge identity runtime for OpenAgenet (OAN) user assistants, resource services, and agents. It provides multi-identity storage, controlled signing, mutual verification, session policy, and protocol integration.

`oan-identity-runtime` is the core new module in the OAN identity adoption plan. It consumes existing OAN DID Documents, registration VCs, ResourcePackages, Discovery records, and Root/governance evidence without changing the semantics of `did:oan`, Registrar, Discovery, or Root.

## Scope

The first Runtime release is a local process or embeddable library responsible for:

- managing user-assistant, controller, and resource DIDs;
- storing public identity material, state, and private-key references in an encrypted store;
- using private keys through a Key Provider without exporting them to agents, plugins, or protocol profiles;
- creating controlled `SignIntent` requests bound to purpose, audience, operation, and policy;
- verifying DID Documents, registration VCs, ResourcePackages, Discovery responses, and session evidence;
- managing challenges, sessions, nonces, replay protection, audit records, and publication recovery;
- providing MCP, A2A, and ordinary HTTP profiles first.

ANP adaptation and dedicated OpenClaw plugins are deferred. Skill-enabled OpenClaw/Hermes agents are planned users of the community Skill verification workflow; other modes may use MCP/A2A/HTTP entry points; a dedicated Hermes plugin and version-specific interoperability are not yet implemented. ANP is used only as a reference for multi-DID stores, key-purpose isolation, HTTP Message Signatures, recovery state machines, and Gateway/Receiver layering.

## Boundary

The Runtime manages edge identities and cryptographic operations. It does not replace official Root, Registrar, or Discovery services, and it does not use a controller identity as the business-message signing identity of a resource. Protocol profiles accept structured intents or exact signing inputs and do not expose arbitrary byte-signing APIs.

The community Skill is a formal registration/discovery and mutual-verification workflow entry. Its local adapter can call the same Runtime core as CLI/MCP tools, without reading long-term private keys. Independent identity verification uses purpose/scope-bound public messages and requires no business endpoint or Sidecar. A completed handshake alone does not protect subsequent business calls. The Runtime now contains the feasibility-slice handshake, protected invocation, encrypted provider, durable replay, and authenticated IPC implementations; protocol-specific production adapters remain separately gated. Sidecars and Gateways depend on the Runtime through controlled interfaces and do not duplicate identity storage or signing logic.

## Planned Layers

- `identity-catalog`: DIDs, ResourcePackages, registration VCs, Discovery sources, and relationships
- `encrypted-store`: encrypted local indexes, key references, state, and audit records
- `key-provider`: OS Keychain and encrypted-file providers first; TPM, TEE, KMS, and HSM as later options
- `policy-session`: SignIntent, policy, challenge, session, nonce, and approval binding
- `verification`: DID, VC, ResourcePackage, Root evidence, and `VerificationResult`
- `profiles`: MCP, A2A, and HTTP request, response, event, and result binding
- `tools`: Skill-free CLI, JSON, and MCP entry points

## Security Rules

- Private keys are used by default only in user- or enterprise-controlled deployments.
- The Runtime never exposes long-term private keys to models or untrusted plugins.
- Controller authority does not substitute for resource keys. A controller-capable assistant may communicate under its own DID.
- Channel authentication is not automatically business-identity authentication.
- An unadapted peer must never be reported as having completed OAN mutual authentication.

## Development status

A buildable development framework and executable F1–F5 feasibility slice are present. The slice is limited to the tested MCP profile/transport and lab identities; it is not yet a production identity service or a complete set of protocol adapters. Detailed design, development planning, and framework reviews are maintained separately in `oan-design-docs`. Source code uses English by default.

## License

This repository is licensed under `Apache-2.0` to support OAN ecosystem adoption.

## Integration test cases

See [test-cases/README.md](test-cases/README.md) for the lab-based scenario matrix, executable cases, run commands and explicit blocked end-to-end gates. Test identities are reused from `oan-agent-integration-lab`; no identity keys are copied into this repository.
