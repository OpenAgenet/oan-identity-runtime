<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!-- Initial author: JINLIANG XU; Email: jlxufly@gmail.com -->
# Runtime integration test cases

This is an executable test specification, not a production import/handshake service. It guides Runtime development using the lab's actual registered identities and native services.

## Run

```sh
# Lab repository: install its pinned dependencies and compile actual protocol fixtures.
cd ../oan-agent-integration-lab
npm ci --ignore-scripts
npm run build
node scripts/check-identities.mjs
cd ../oan-identity-runtime
npm ci
npm run test:lab
# Existing regression suite remains separate:
npm run typecheck
npm test
```

`test:lab` builds Runtime then runs all `test-cases/lab/*.test.mjs`. The protocol cases dynamically import the lab build and official SDK clients from the lab dependency tree. No component production dependency is added. They open only ephemeral `127.0.0.1` ports, use an OS temporary directory/ledger, close clients/listeners and remove their own directory. They do not use or modify deployed services/4101–4302. Missing build/dependencies fail with module-load errors; build the lab first.

Optional read-only Discovery check (PowerShell):

```powershell
$env:OAN_LAB_LIVE='1'
npm run test:lab
Remove-Item Env:OAN_LAB_LIVE
```

This queries only the five manifest DIDs through the official website gateway (`https://www.openagenet.xyz`), with a 15-second request timeout, and compares exact saved/current documents. Stale local material is a failure to reconcile, not permission to register replacements. `OAN_LAB_ROOT` overrides checkout location. No registration POST is made.

## Implemented and pending cases

| ID | Scenario / setup | Action and required assertion | Scope / file |
|---|---|---|---|
| RT-01 | A2A A→B/B→A, A2A A→MCP, Hermes A→B/B→A | Load actual Identity/DID/VC; key imports into MemoryKeyProvider; sign with resource DID; expected peer verifies JWS; controller DID never replaces sender | Implemented crypto integration; `runtime.test.mjs` |
| RT-02 | Every RT-01 pair | Replay, altered payload, wrong audience/sender/controller, operation, session, request ID, protocol, expired proof, wrong verification key, foreign tenant and challenged session must fail with expected error; identity listing omits secrets | Implemented component negative cases; no network handshake |
| RT-03 | MCP signs result to A2A caller | Bind response to exact signed-request digest, service and request; reject missing/wrong request digest | Implemented signed response correlation |
| RT-04 | Reload all seven fixed identities twice | Same DID and private JWK; no identity generation or registration | Implemented fixture stability, **not** durable Runtime restart |
| RT-05 | Five official Discovery records | Explicit opt-in; exact document, version, DID and callable endpoint match saved material | Opt-in live L0 read; no trust-chain validation |
| RT-06 | Framework capability report | Installed handlers only; synchronous capability scope matches implementation | Implemented truthfulness gate |
| RT-07 | Hermes Skill/CLI/MCP independent mutual verification | Actual begin/accept/advance/confirm from both resources; verify DID/VC/status/governance, possession and both confirmations; reject reflection, old transcript and missing confirmation | G3 implemented: tools-mutual and skill-hermes-mutual; pinned Root evidence, live governance remains unknown |
| RT-08 | Restart after accepted request | Restart host/store; same key reference/DID; old nonce rejected; outstanding attempt reconciled without new DID | G3/G4 synchronous disk/replay/operation receipt tests implemented; complete lifecycle remains G5 |
| RT-09 | Actual MCP HTTP and A2A lab implementation | Test host validates Runtime-signed request before official native client call; ledger is zero for tampering, one after valid call, remains one after replay; resource signs native result, caller rejects altered result; direct native bypass deliberately succeeds and ledger reaches two | Implemented initial composition; `protocol.test.mjs`; **not L2** |
| RT-10 | MCP stdio, Hermes native adapter and Skill tool workflow | Same fault matrix through real process/transport/tool host, using correct resource keys; close/timeout cleanup; no model-visible private key | G3/G4 real stdio/HTTP tool and Skill workflow drivers implemented; native Hermes outbound remains G6 |
| RT-11 | Trusted import and evidence | Missing/mismatched VC, wrong issuer, revoked status, stale Root/governance evidence quarantine identity; encrypted backup/restore and wrong-key recovery | Planned: IdentityHost/evidence/storage composition; catalog.add in fixture is not trusted import |
| RT-12 | Events and task lifecycle | Real A2A stream and MCP events: ordered signed chunks, request/task/result correlation, cancellation, truncation and terminal proof | Planned: StreamVerifier/profile implementation |

`fixtures.mjs` is a trusted **test-only** host: it marks catalog records registered and provides a pre-authenticated session to isolate signing behavior. It does not authenticate a caller over IPC, validate a registration VC signature or run a handshake. It loads private keys only in-process. RT-09 verifies signatures before a real call but does not embed proofs into the native wire protocol; its reverse response is signed by a test-host Runtime, not by a protected native service. Its explicit bypass demonstration prevents interpreting it as deployed L2 enforcement. A2A `record:<value>` and MCP `record` execute real lab ledger code; temporary endpoints are distinct from registered deployment endpoints.

## Development gates

1. Keep these crypto/binding cases passing while implementing trusted import, evidence and handshake; replace fixture sessions with actual verified transitions in a **new** end-to-end case.
2. Implement MCP stdio then HTTP invocation with exact request/result coverage; add actual transport-level proof carriage and result verification before trusted output.
3. Add real A2A synchronous Task and Hermes transport integration, then streaming/event assertions; preserve protocol-native behavior.
4. Add durable replay and encrypted persistent host restart tests. Move skipped cases to runnable only with independent ledger and evidence assertions. Do not set framework capability flags merely to satisfy tests.

## Shared laboratory contract

Use a sibling checkout of `oan-agent-integration-lab`, or set `OAN_LAB_ROOT` to its absolute path. Baseline: lab commit `35ad408`, five resource packages `0.1.0.2`; later metadata changes are read from the manifest rather than fixed hashes. Node 22.13+ and Rust 1.98+ are the component baselines. Keep dependency repositories (`oan-sdk-ts`, `oan-protocol-common`) beside these repositories as required by their existing build configuration.

| Lab actor | Resource kind / wire protocol | Same-host service | Controller |
|---|---|---|---|
| a2a-a | agent_service / A2A 1.0 | http://127.0.0.1:4101/ | controller-a |
| a2a-b | agent_service / A2A 1.0 | http://127.0.0.1:4102/ | controller-a |
| mcp | mcp_server / SDK-negotiated MCP Streamable HTTP | http://127.0.0.1:4201/mcp | controller-a |
| hermes-a | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4301/ | controller-b |
| hermes-b | agent_service / pinned native Hermes A2A adapter | http://127.0.0.1:4302/ | controller-b |

`config/oan-identities.json` is the source of real DIDs and relative paths. Reuse the resource key for peer communication; controller keys authorize registration/document updates and are not proxy delegation. These tests never create new DIDs, register resources, change production nodes, deploy services, or print private keys. Do not copy lab keys into these component repositories. The private lab checkout retains the owner-approved test keys.

Default tests are offline. A missing lab fixture is a **failure**, not a synthetic identity fallback. Scheduled network or server tests require a separately prepared lab. Loopback always means the caller's current host. Existing shared OS-user fixtures cannot prove isolation against a hostile local process.

## Result and evidence rules

- `implemented`: executable test of existing public component code. State the exact scope; a passing boundary unit test is not a proxy/handshake pass.
- `opt-in`: requires an explicit switch, public read-only network requests or a prepared external lab.
- `blocked`: named missing implementation; displayed as skipped/ignored, never counted as passed. Do not remove the gate until the real implementation and acceptance assertions exist.
- Unit test doubles only exercise specified binding gates. A pre-authenticated session fixture does not prove a handshake. Loading a saved VC does not verify the issuer or governance chain.
- L0 is registration/discovery/endpoint resolution. L1 additionally needs real DID/VC/trust/status checks. Independent mutual verification needs signed peer possession and final confirmation. L2 additionally binds actual requests and responses, policy, time, audience, correlation and replay, and prevents bypass before effects.
- No test may silently downgrade L2 to L1 or native protocol success. Expired/unavailable evidence is unknown/rejected, never authenticated.

## Future end-to-end fault matrix

For each enabled A2A, MCP HTTP, MCP stdio and Hermes entry point: positive call executes exactly once; altered request, wrong audience, wrong sender, controller-key substitution, wrong operation/service/session/request, expired proof, forged principal and bypass execute zero times. Replay executes only its first valid attempt. Response tampering/substitution executes once but the caller rejects the result as untrusted. Use unique markers and read the actual lab ledger separately from component reports. Responses bind the request digest and peer DID; streaming tests bind task/request, sequence, previous digest and signed terminal state, including truncation, reordering, cancellation and disconnect. Restart tests require durable replay state and reject a previously consumed nonce after process restart.

Future live Hermes tests use the pinned upstream adapter in transport mode, no model. Full gateway/model behavior and autonomous Skill execution are separate optional checks. MCP stdio must use the official client and process ownership rules; it is not remote mutual authentication merely because messages carry DIDs. Existing OAuth/Bearer and MCP headers must retain their protocol semantics.

G3/G4 product gates use Runtime `DurableIdentityVerification`, `SynchronousInvocation`, `NativeSynchronousBoundary` and the pinned A2A handler/client mapping. The lab acceptance drivers are in `adapters/g3-g4-*.mjs`, `adapters/tools-mutual.mjs`, `adapters/hermes-skill.mjs`, and `test-cases/g3-g4/`. They verify actual handler effects and native response proofs, independently of the earlier RT-09 demonstration. Run `scripts/verify-g3-g4.sh` in the isolated Ubuntu workspace; complete stream/Sidecar/Gateway gates remain blocked.
