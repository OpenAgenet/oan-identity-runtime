// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { createJwkOanSigner, type OanSigner } from '@openagenet/oan-sdk-ts';
import { sealBlob, openBlob } from '../store/encryption.js';
import type { EncryptedBlobStore } from '../store/index.js';
import type { KeyProvider } from './index.js';
import { RuntimeError } from '../errors.js';
/** Host-only vault API. No key or decrypted record operation is exposed as a tool. */
export class EncryptedKeyProvider implements KeyProvider {
  readonly id = 'encrypted';
  private key?: Uint8Array;
  private generation = 0;
  private expiresAt = 0;
  constructor(private readonly store: EncryptedBlobStore, private readonly now = Date.now) {}
  unlock(key: Uint8Array, expiresAt = this.now() + 300_000): void {
    if (key.length !== 32 || !Number.isFinite(expiresAt) || expiresAt <= this.now()) throw new RuntimeError('invalid_unlock_lease');
    this.lock(); this.key = new Uint8Array(key); this.expiresAt = expiresAt;
  }
  lock(): void { this.key?.fill(0); this.key = undefined; this.generation++; this.expiresAt = 0; }
  private check(generation = this.generation): Uint8Array {
    if (this.now() >= this.expiresAt) this.lock();
    if (!this.key || generation !== this.generation) throw new RuntimeError('vault_locked');
    return this.key;
  }
  async readRecord<T>(id: string): Promise<{ generation: number; value: T } | undefined> {
    const epoch = this.generation; this.check(epoch);
    const row = await this.store.load(id);
    const key = this.check(epoch);
    return row ? {generation: row.generation, value: JSON.parse(openBlob(row.ciphertext, key, id, row.generation)) as T} : undefined;
  }
  async commitRecords(records: readonly {id: string; expectedGeneration: number; value: unknown}[]): Promise<void> {
    const epoch = this.generation, key = this.check(epoch);
    const mutations = records.map(r => ({id:r.id, expectedGeneration:r.expectedGeneration,
      ciphertext:sealBlob(JSON.stringify(r.value), key, r.id, r.expectedGeneration + 1)}));
    this.check(epoch);
    await this.store.commit(mutations); this.check(epoch);
  }
  async importJwk(ref: string, method: string, privateJwk: JsonWebKey): Promise<void> {
    const epoch = this.generation; this.check(epoch);
    const snapshot = structuredClone({method, privateJwk});
    await createJwkOanSigner(snapshot.method, snapshot.privateJwk); this.check(epoch);
    await this.commitRecords([{id:ref, expectedGeneration:0, value:snapshot}]);
  }
  async getSigner(ref: string): Promise<OanSigner> {
    const epoch = this.generation; this.check(epoch);
    const row = await this.readRecord<{method:string; privateJwk:JsonWebKey}>(ref);
    if (!row) throw new RuntimeError('key_missing');
    const signer = await createJwkOanSigner(row.value.method, row.value.privateJwk); this.check(epoch);
    const check = () => { this.check(epoch); };
    return {keyId:signer.keyId, algorithm:'Ed25519', publicKey:async()=>{check(); const result=await signer.publicKey(); check(); return result;},
      signPreparedInput:async bytes=>{check(); const result=await signer.signPreparedInput(bytes); check(); return result;}};
  }
}
