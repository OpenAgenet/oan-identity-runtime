// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { readFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { verifyPinnedRootPackage, canonicalJson, type OanSigner } from '@openagenet/oan-sdk-ts';
import { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import { SqliteBlobStore } from '../store/sqlite.js';
import { SqliteReplayStore } from '../session/index.js';
import { MutualHandshake, type HandshakeScope, type HandshakeMessage } from '../session/handshake.js';
import { LocalIdentityVault } from './vault.js';
import { importRegistrationFiles } from './import-registration.js';
import { PinnedRootEvidenceVerifier } from '../evidence/pinned-root.js';
import { MemoryAuditSink } from '../audit/index.js';
import { RuntimeHostVerifier, type RuntimeHostSessionProof } from './runtime-host.js';
import { IdentityRuntime } from '../runtime.js';
import { PolicyEngine } from '../policy/index.js';

/** Trusted actor-side composition. No network caller may supply paths, pins or keys. */
export async function openRegisteredActor(config: {
  identityRef: string; identityPath: string; didDocumentPath: string; registrationVcPath: string;
  resourcePackage: any; discoveryUrl: string; pins: any; vaultPath: string; masterKey: Uint8Array;
  resolvePackage(did: string): Promise<any>;
  runId?: string;
}) {
  const read = async (path: string) => JSON.parse(await readFile(path, 'utf8'));
  const document = await read(config.didDocumentPath);
  await mkdir(dirname(config.vaultPath), { recursive: true, mode: 0o700 });
  const store = new SqliteBlobStore(config.vaultPath);
  const keys = new EncryptedKeyProvider(store);
  try {
  keys.unlock(config.masterKey);
  const caller = { callerId: config.identityRef, tenantId: 'oan-reference' };
  const vault = new LocalIdentityVault(keys, new MemoryAuditSink(), {
    rootDid: config.pins.anchor.rootDid,
    verifier: new PinnedRootEvidenceVerifier(config.pins.anchor, new Date().toISOString(), 300_000,
      { registrar: config.pins.registrar, requirePrivateVc: true }),
  });
  if (!(await vault.list()).some(item => item.id === config.identityRef)) await importRegistrationFiles({ ...config, vault, caller });
  const record = await vault.get(config.identityRef);
  if (record.did !== document.id) throw new Error('runtime_actor_did_mismatch');
  const signer: OanSigner = await keys.getSigner(record.keyRef);
  // Reopening a vault must validate current public evidence and key bindings,
  // rather than inheriting the previous process's import verdict.
  const verification = await new PinnedRootEvidenceVerifier(config.pins.anchor, new Date().toISOString(), 300_000,
    { registrar: config.pins.registrar, requirePrivateVc: true }).verifyRegistration({ didDocument: document, resourcePackage: config.resourcePackage,
      registrationVc: await read(config.registrationVcPath), expectedResourceDid: record.did, trustAnchor: { mode: 'pinned-root', rootDid: config.pins.anchor.rootDid } });
  if (!verification.valid || canonicalJson(record.didDocument) !== canonicalJson(document)
    || (await signer.publicKey()).x !== document.verificationMethod?.find((method: any) => method.id === signer.keyId)?.publicKeyJwk?.x) {
    throw new Error('runtime_actor_recovery_evidence_invalid');
  }
  const resolvePeer = async (did: string) => {
    const resourcePackage = did === record!.did ? config.resourcePackage : await config.resolvePackage(did);
    return { ...await verifyPinnedRootPackage({ resourcePackage, expectedDid: did, anchor: config.pins.anchor,
      observedAt: new Date().toISOString(), maxAgeMs: 300_000 }), did };
  };
  const replay = new SqliteReplayStore(`${config.vaultPath}.replay`);
  const host = new RuntimeHostVerifier(record.did, signer, resolvePeer, replay, config.runId ? { runId: config.runId, tenantId: caller.tenantId } : undefined);
  const handshake = new MutualHandshake(record.did, signer, resolvePeer);
  return {
    did: record.did, host, handshake, resolvePeer,
    async installSession(proof: RuntimeHostSessionProof) { return host.addVerifiedSession(proof); },
    async signRequest(proof: RuntimeHostSessionProof, requestId: string, rawBodyDigest: string, operation: string,
      httpBinding?: { method: string; target: string; mcpSessionId: string }) {
      const session = await host.addVerifiedSession(proof);
      const policy = new PolicyEngine([{ ...caller, identityRef: config.identityRef,
        audienceDid: session.peerDid, purpose: 'request', protocol: proof.scope.protocol, operation }]);
      const runtime = new IdentityRuntime({ catalog: vault, keys: { resolve: ref => keys.getSigner(ref) },
        policy, sessions: { requireAuthenticated: async (id, local, peer) => {
          if (id !== session.id || local !== session.localDid || peer !== session.peerDid) throw new Error('session_scope_mismatch');
          return session;
        } }, audit: new MemoryAuditSink() });
      return runtime.signIntent(caller, { identityRef: config.identityRef, audienceDid: session.peerDid,
        purpose: 'request', protocol: proof.scope.protocol, protocolVersion: proof.scope.protocolVersion,
        serviceRef: proof.scope.serviceRef, sessionId: session.id, requestId, operation, payload: { rawBodyDigest, ...(httpBinding ? { httpBinding } : {}), ...(config.runId ? { runId: config.runId, tenantId: caller.tenantId } : {}) } });
    },
    close() { keys.lock(); replay.close(); store.close(); },
  };
  } catch (error) { keys.lock(); store.close(); throw error; }
}

/** Transport-independent four-message exchange; callers transport only public messages. */
export async function establishActorSession(initiator: Awaited<ReturnType<typeof openRegisteredActor>>,
  scope: HandshakeScope, exchange: (phase: 'accept' | 'advance', message: HandshakeMessage) => Promise<HandshakeMessage>) {
  const hello = await initiator.handshake.begin(scope);
  const server = await exchange('accept', hello);
  const client = (await initiator.handshake.advance(hello.body.sessionId, server)).reply!;
  const confirmed = await exchange('advance', client);
  await initiator.handshake.advance(hello.body.sessionId, confirmed);
  const proof: RuntimeHostSessionProof = { scope, transcript: [hello, server, client, confirmed] };
  await initiator.installSession(proof);
  return proof;
}
