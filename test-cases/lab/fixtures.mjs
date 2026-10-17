// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { IdentityCatalog, MemoryKeyProvider, KeyProviderRegistry, PolicyEngine, MemoryAuditSink, IdentityRuntime, ReplayCache, verifyPinnedMessage } from '../../dist/index.js';

export const labRoot = resolve(process.env.OAN_LAB_ROOT ?? fileURLToPath(new URL('../../../oan-agent-integration-lab/', import.meta.url)));
export const read = async path => JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, ''));
export async function loadLab() {
  let manifest;
  try { manifest = await read(resolve(labRoot, 'config/oan-identities.json')); }
  catch { throw new Error('lab_fixture_missing: clone oan-agent-integration-lab beside this repository or set OAN_LAB_ROOT'); }
  const actors = {};
  for (const [name, actor] of Object.entries({...manifest.controllers, ...manifest.resources})) {
    const path = resolve(labRoot, actor.materials.oanIdentity);
    assert.ok(path.startsWith(resolve(labRoot, '.state/identities') + sep));
    const identity = await read(path);
    const document = await read(resolve(labRoot, actor.materials.didDocument));
    const vc = await read(resolve(labRoot, actor.materials.registrationVc));
    assert.equal(identity.did, actor.did); assert.deepEqual(identity.didDocument, document);
    assert.equal(vc.credentialSubject.id, actor.did);
    assert.equal(vc.credentialSubject.packageVersion, actor.packageVersion);
    assert.equal(document.controller, actor.controllerDid);
    actors[name] = { ...actor, identity, document, vc };
  }
  assert.equal(Object.keys(actors).length, 7);
  assert.equal(new Set(Object.values(actors).map(a => a.did)).size, 7);
  return { manifest, actors };
}
// Test-only session fixture. This DOES NOT perform a handshake or verify VC/governance trust.
export async function host(local, peer, protocol) {
  const catalog = new IdentityCatalog();
  await catalog.add({ id:'resource', did:local.did, kind:'resource', status:'registered', verificationMethodId:local.identity.verificationMethodId, keyRef:'resource-key', didDocument:local.document, evidenceRefs:[] });
  const keys = new MemoryKeyProvider();
  await keys.importJwk('resource-key', local.identity.verificationMethodId, local.identity.privateKeyJwk);
  const audit = new MemoryAuditSink();
  const session = { id:'test-session', localDid:local.did, peerDid:peer.did, state:'authenticated', expiresAt:new Date(Date.now()+60000).toISOString() };
  const runtime = new IdentityRuntime({ catalog, audit,
    keys:new KeyProviderRegistry([keys], [{ id:'resource-key',providerId:'memory',providerKeyId:'resource-key',purposes:['request','response'] }]),
    policy:new PolicyEngine(['request','response'].map(purpose => ({callerId:'lab-host',tenantId:'lab',identityRef:'resource',audienceDid:peer.did,purpose,protocol,operation:'record'}))),
    sessions:{async requireAuthenticated(){return session;}} });
  const intent = { identityRef:'resource',audienceDid:peer.did,purpose:'request',protocol,protocolVersion:'lab-envelope-v1',operation:'record',serviceRef:peer.document.service[0].id,sessionId:session.id,requestId:'lab-request',payload:{value:'test-only'} };
  const caller = { callerId:'lab-host',tenantId:'lab' };
  const pinned = {senderDid:local.did,audienceDid:peer.did,verificationMethod:local.identity.verificationMethodId,publicKeyJwk:local.identity.publicKeyJwk,serviceRef:intent.serviceRef,protocolVersion:intent.protocolVersion,operation:intent.operation,sessionId:session.id,requestId:intent.requestId,purpose:'request',protocol,replay:new ReplayCache()};
  return {runtime,session,intent,caller,pinned,audit,keys};
}
export { ReplayCache, verifyPinnedMessage };
