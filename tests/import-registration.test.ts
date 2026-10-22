// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createOanIdentityRecord, signDidDocumentProof } from '@openagenet/oan-sdk-ts';
import { EncryptedKeyProvider, importRegistrationFiles, LocalIdentityVault, MemoryAuditSink } from '../src/index.js';
import { SqliteBlobStore } from '../src/store/sqlite.js';

test('trusted Actor host imports matching registration files through encrypted vault', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'oan-import-registration-'));
  const store = new SqliteBlobStore(join(dir, 'vault.sqlite'));
  const keys = new EncryptedKeyProvider(store); keys.unlock(randomBytes(32));
  const identity = await createOanIdentityRecord({ label: 'actor-import', resourceType: 'skill', kind: 'agent' });
  identity.didDocument = await signDidDocumentProof(identity.didDocument, identity);
  const files = { identityPath: join(dir, 'identity.json'), didDocumentPath: join(dir, 'did-document.json'), registrationVcPath: join(dir, 'registration-vc.json') };
  const vc = { id: 'test-vc' };
  await Promise.all([[files.identityPath, identity], [files.didDocumentPath, identity.didDocument], [files.registrationVcPath, vc]].map(([path, data]) => writeFile(path as string, JSON.stringify(data), 'utf8')));
  const resourcePackage = { resourceDid: identity.did, packageHash: 'sha256:test', rootProof: { rootDid: 'did:oan:root' } } as any;
  const vault = new LocalIdentityVault(keys, new MemoryAuditSink(), { rootDid: 'did:oan:root', verifier: { verifyRegistration: async input => ({ valid: input.registrationVc === vc || JSON.stringify(input.registrationVc) === JSON.stringify(vc), checks: [{ name: 'privateVc', status: 'passed' }] }) } });
  const input = { vault, caller: { callerId: 'actor-host' }, identityRef: 'actor', ...files, resourcePackage, discoveryUrl: 'https://www.openagenet.xyz/discovery/resources/query' };
  try {
    assert.equal((await importRegistrationFiles(input)).status, 'registered');
    assert.equal((await vault.get('actor')).did, identity.did);
    assert.equal((await keys.getSigner('host:key:actor')).keyId, identity.verificationMethodId);
    assert.equal((await readFile(join(dir, 'vault.sqlite'))).includes(Buffer.from(identity.privateKeyJwk.d as string)), false);
    await assert.rejects(importRegistrationFiles({ ...input, identityRef: 'other', resourcePackage: { ...resourcePackage, resourceDid: 'did:oan:wrong' } }), /registration_import_did_mismatch/);
    assert.equal((await vault.list()).length, 1);
    await assert.rejects(importRegistrationFiles({ ...input, identityRef: 'untrusted', registrationVcPath: files.didDocumentPath }), /registration_evidence|registration_vc|invalid_identity|identity_import/i);
    assert.equal((await vault.list()).length, 1, 'rejected registration material must not commit another identity');
    await assert.rejects(keys.getSigner('host:key:untrusted'), /not_found|missing|unknown/i);
  } finally { keys.lock(); store.close(); await rm(dir, { recursive: true, force: true }); }
});
