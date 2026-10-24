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

ANP adaptation and dedicated OpenClaw plugins are deferred. Hermes can use the community Skill verification workflow through its native Skill/terminal tools; other hosts require their own integration checks. A dedicated Hermes plugin and native outbound adaptation remain later gates. ANP is used as a reference for stores, key-purpose isolation, recovery state machines, and Gateway/Receiver layering.

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

A buildable development framework, G0–G2 local identity/publication entry points, and executable F1–F5 feasibility slice are present. G0–G2 provide encrypted identity import, leased providers, controlled signing, pinned-Root evidence checks, durable publication recovery, and CLI/MCP tools. Actual installed tools depend on trusted host configuration (`RuntimeToolHost.list()`); the default CLI exposes only public discovery and resolution. Private registration credentials remain in host-local material files and are not returned by publication tools. Rejected version conflicts permit an approved same-DID revision; uncertain submissions require reconciliation before any further write.

G3/G4 add `DurableIdentityVerification`, `SynchronousInvocation` and `NativeSynchronousBoundary`. Configured CLI/MCP/Skill hosts share the same encrypted, caller-scoped four-message workflow. The native boundary verifies actual MCP stdio/Streamable HTTP tool objects, A2A synchronous SendMessage/Task objects, and HTTP application envelopes before executing or returning trusted output. The host pins native descriptors/codecs, peer identity, evidence resolver and operation policy. Metadata carriers preserve unrelated metadata; A2A codecs must use the pinned SDK conversion on both sides. Default tools still offer only public directory access.

Sessions currently expire after 60 seconds. Inspect returns local state and the last public outgoing message for recovery; exact final confirmation may be resent without creating a new session. Durable nonce storage and operation receipts reject duplicate effects, including a new nonce for the same operation ID. A dispatched call with an unknown outcome is never automatically resent; reconcile using its local receipt. Provider/master-key custody remains host-owned and is never configured from peer input.

Protected HTTP/SSE, Sidecar/Gateway and Hermes-hosted A2A/MCP paths have been exercised in reference integration deployments. The synchronous A2A handler wrapper still rejects unsupported operations; this evidence does not imply every transport or asynchronous operation has a turnkey adapter. Pinned Root snapshots do not establish live chain/revocation status. Detailed design and development evidence are maintained in `oan-design-docs`. Runtime production code never imports the integration lab. Source code uses English by default.

## Embedding the synchronous boundary

For an Actor that has already registered, a trusted local host can call
`importRegistrationFiles` with its own OAN Identity, DID document and VC paths,
the freshly resolved ResourcePackage, a pinned evidence verifier and a
`LocalIdentityVault`. The helper checks DID agreement and issues a short-lived
import lease; the Vault verifies document/key/registration evidence and commits
the key and material to encrypted storage atomically. Do not expose this helper
as an agent tool or accept paths/trust configuration from a peer. The host can
bind authenticated IPC with `listenAuthenticatedRuntimeIpc`; on Windows this
accepts only a local named pipe and disables Node's broad read/write sharing.

Construct a caller-scoped `DurableIdentityVerification` with an encrypted provider, identity catalog, signing key resolver, audit sink, verified peer resolver and host authorization callback. Pass it to `IdentityRuntime` and `SynchronousInvocation` together with a durable replay store, encrypted operation journal and a pinned `SynchronousProfile`. Install `NativeSynchronousBoundary.handle()` at the actual native business handler; use `call()` on the client before exposing a result. `metadataField` is `_meta` for MCP and `metadata` for A2A/envelope objects. The optional codec must produce the exact canonical native object on both sides. Unsupported operations must be denied at the host, and native TLS/OAuth stays enabled.

`RuntimeToolHost({caller, directory, verification, invocation})` exposes only installed workflow/call handlers. Its invocation adapter maps a local `routeRef` to a preconfigured boundary/transport and forwards the optional stable `requestId`; it must not accept arbitrary destinations or caller claims. CLI startup uses `--host trusted-host.mjs` exporting `createToolHost()`. Community Skill uses its corresponding `--identity-host` adapter. Neither entry exposes arbitrary signing or key export.

## License

This repository is licensed under `Apache-2.0` to support OAN ecosystem adoption.

## Integration test cases

See [test-cases/README.md](test-cases/README.md) for the lab-based scenario matrix, executable cases, run commands and explicit blocked end-to-end gates. Test identities are reused from `oan-agent-integration-lab`; no identity keys are copied into this repository.

## Protected native HTTP clients

`createVerifiedHttpFetch` is a reusable native SDK fetch hook. A trusted host
provides signing and verification callbacks through embedded Runtime or local
IPC. Pin the endpoint and allowed methods; the adapter blocks redirects and
oversized responses, verifies before returning, and removes the OAN terminal SSE
proof before the native protocol SDK parses events. Business code keeps native
A2A/MCP operations and cancellation signals and never handles key material.
This bounded response adapter buffers until verification; it does not expose
unverified streamed chunks as trusted data. Gateway/Sidecar may still forward
incrementally for provisional display.

Runtime owns identity and cryptography; Sidecar owns resource ingress; Gateway
owns deployment/tenant routing. Registration/discovery remain SDK/Skill workflows.
The demo reference composes these APIs and does not constitute a Runtime dependency.

`openRegisteredActor` accepts optional trusted-host `tenantId`, `callerId` and
`policyRules`. Defaults retain `oan-reference`, the identity reference as caller,
and the existing per-request policy. Explicit rules are snapshotted at startup
and must match caller, tenant, identity, peer, protocol and operation; `[]` denies
all signing. These options come from local trusted configuration, never peer
request data. The optional `runId` binds an isolated run within that tenant.

## Adoption boundary and native response proof profile

L0 uses the community Skill or SDK without this Runtime. For local custody and
independent mutual verification, configure Runtime with your own identities,
trust pins and caller/peer policy. For L2, wrap the selected native protocol
boundary or use an external Sidecar; add Gateway only when routing requires it.
The host owns handshake transport and business authorization. No demo launcher,
scenario graph, process manager, fixed port or server account is required.

`createNativeProofHttpFetch` composes the existing bounded fetch boundary with
native Gateway/Sidecar response-proof verification. Supply the endpoint, allowed
methods, local/peer DIDs, explicit `responseProofKind`, verified peer resolver,
and a host-controlled request signer. It computes and binds the exact request
body digest and verifies the actual response bytes/status/correlation before
returning them to the native SDK. `onVerified` exposes a public receipt only.
The endpoint and proof kind come from trusted route configuration, not response
claims. No automatic registration, peer selection, authorization or retry occurs.
See [examples/native-proof-client.mjs](examples/native-proof-client.mjs) for an
independent fetch-hook composition. It uses your own trusted host module and
requires no demo repository. SSE is buffered until its terminal proof succeeds;
this is not per-event authenticated live delivery.

New hosts may pass opaque `requestContext` bindings and `requireHttpBinding` to
`openRegisteredActor` / `RuntimeHostVerifier`. Runtime compares these configured
values without interpreting business tasks. Reserved digest/HTTP/tenant fields
cannot be overridden. `runId` and the `oan-reference` default tenant are retained
only for compatibility; new deployments should set their own caller, tenant and
explicit `policyRules` (an empty list denies signing). Omitted rules retain the
legacy trusted-host per-request behavior, not a business authorization policy.
Run-specific values and task-derived ACLs belong to the application.

The CLI's default public tools remain L0 only. Private tools require a trusted
host configuration; exposing Runtime as an MCP tool does not protect another
MCP server. The current standalone host loads supplied evidence/session files;
it is not an application orchestrator or a turnkey dynamic bootstrap service.
Source-workspace installation is currently required (`private: true` with a
sibling SDK dependency); this is distinct from public npm availability.

For a registered actor, prefer `createActorNativeHttpFetch({ actor, session,
endpoint, methods, responseProofKind, operation })`. It reuses the actor's
verified resolver and policy-controlled `signRequest`, builds the native request
headers, and binds HTTP method/target/MCP session automatically. `operation` is
an explicit string or a trusted native-request mapper; the host chooses the
mapping and its allowlist. The adapter never derives permissions from response
claims or a task graph. Establish the verified session using the existing
transport-independent handshake first. Session expiry requires an explicit new
handshake; business requests are never automatically retried.

`requestContext` is bounded and snapshotted, accepts only plain string maps,
and cannot override protocol digest/HTTP/tenant fields. Conflicting legacy
`runId` values are rejected. With `requireHttpBinding`, an incomplete binding
is rejected at signing as well as verification. These checks do not implement
application business authorization.
