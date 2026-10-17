// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { DidDocument } from '@openagenet/oan-sdk-ts/protocol-types';
import { parseDidOan } from '@openagenet/oan-sdk-ts';
import { RuntimeError } from '../errors.js';
export type IdentityStatus = 'local_ready' | 'registered' | 'quarantined' | 'disabled';
/** Trusted host record. Never return it directly to an agent or across IPC. */
export interface IdentityRecord {
  id: string; did: string; kind: 'controller' | 'resource'; status: IdentityStatus;
  verificationMethodId: string; keyRef: string; didDocument: DidDocument; evidenceRefs: string[];
}
export interface PublicIdentity {
  id: string; did: string; kind: IdentityRecord['kind']; status: IdentityStatus; verificationMethodId: string;
}
export function publicIdentity(record: IdentityRecord): PublicIdentity {
  const { id, did, kind, status, verificationMethodId } = record;
  return { id, did, kind, status, verificationMethodId };
}
/** Async port permits persistent catalog implementations without changing the Facade. */
export interface IdentityRepository {
  get(id: string): Promise<IdentityRecord>;
  list(): Promise<IdentityRecord[]>;
}
export interface IdentityRepositoryWriter extends IdentityRepository {
  add(record: IdentityRecord): Promise<void>;
}
/** Development host catalog; production import verifies evidence before writing here. */
export class IdentityCatalog implements IdentityRepositoryWriter {
  private readonly records = new Map<string, IdentityRecord>();
  async add(record: IdentityRecord): Promise<void> {
    parseDidOan(record.did);
    if (record.didDocument.id !== record.did || !record.id || !record.keyRef || !record.verificationMethodId.startsWith(record.did + '#')) throw new RuntimeError('identity_catalog_binding_mismatch');
    rejectSecrets(record.didDocument);
    if (this.records.has(record.id) || [...this.records.values()].some(r => r.did === record.did)) throw new RuntimeError('identity_already_exists');
    this.records.set(record.id, structuredClone(record));
  }
  async get(id: string): Promise<IdentityRecord> {
    const record = this.records.get(id);
    if (!record) throw new RuntimeError('identity_not_found');
    return structuredClone(record);
  }
  async list(): Promise<IdentityRecord[]> { return [...this.records.values()].map(r => structuredClone(r)); }
}
function rejectSecrets(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  for (const [name, entry] of Object.entries(value)) {
    if (['privateKeyJwk', 'privateKeyMultibase', 'privateKeyBase58', 'privateKeyHex', 'd'].includes(name)) throw new RuntimeError('secret_in_public_material');
    rejectSecrets(entry);
  }
}
