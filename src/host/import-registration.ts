// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { readFile } from 'node:fs/promises';
import { LocalIdentityVault } from './vault.js';
import type { CallerContext } from '../policy/index.js';
import type { IdentityImportBundle } from './index.js';
import { digestJson } from '../verification/index.js';
import { RuntimeError } from '../errors.js';

/** Trusted Actor host only. Paths and Discovery package are supplied by host configuration, never peer input. */
export async function importRegistrationFiles(input: {
  vault: LocalIdentityVault; caller: CallerContext; identityRef: string;
  identityPath: string; didDocumentPath: string; registrationVcPath: string;
  resourcePackage: NonNullable<IdentityImportBundle['resourcePackage']>;
  discoveryUrl: string;
}) {
  if (!input.identityRef || !input.resourcePackage || !/^https:\/\//.test(input.discoveryUrl)) throw new RuntimeError('registration_import_configuration_invalid');
  const read = async (path: string) => JSON.parse(await readFile(path, 'utf8'));
  const [identity, didDocument, registrationVc] = await Promise.all([
    read(input.identityPath), read(input.didDocumentPath), read(input.registrationVcPath),
  ]);
  if (!identity?.did || identity.did !== didDocument?.id || identity.did !== input.resourcePackage.resourceDid)
    throw new RuntimeError('registration_import_did_mismatch');
  if (!registrationVc || typeof registrationVc !== 'object' || !input.resourcePackage.rootProof)
    throw new RuntimeError('registration_import_evidence_missing');
  const bundle: IdentityImportBundle = {
    identity, didDocument, registrationVc, resourcePackage: input.resourcePackage,
    sources: [{ kind: 'discovery', uri: input.discoveryUrl }],
  };
  const lease = input.vault.issueImportLease(input.caller, input.identityRef, await digestJson(bundle), new Date(Date.now() + 60_000).toISOString());
  return input.vault.importIdentity(input.caller, bundle, lease);
}
