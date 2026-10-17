// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { createJwkOanSigner, type OanSigner } from '@openagenet/oan-sdk-ts';
import { sealBlob, openBlob } from '../store/encryption.js';
import type { EncryptedBlobStore } from '../store/index.js';
import type { KeyProvider } from './index.js';
import { RuntimeError } from '../errors.js';
/** Host-only import/unlock. Wrapped signers check the current lock generation on every use. */
export class EncryptedKeyProvider implements KeyProvider {
  readonly id = 'encrypted';
  private key?: Uint8Array;
  private generation = 0;
  constructor(private readonly store: EncryptedBlobStore) {}
  unlock(key: Uint8Array): void { if (key.length !== 32) throw new RuntimeError('invalid_encryption_key'); this.lock(); this.key=new Uint8Array(key); }
  lock(): void { this.key?.fill(0); this.key=undefined; this.generation++; }
  async importJwk(ref: string, method: string, privateJwk: JsonWebKey): Promise<void> {
    if (!this.key) throw new RuntimeError('vault_locked');
    await createJwkOanSigner(method,privateJwk);
    await this.store.compareAndSwap(ref,0,sealBlob(JSON.stringify({method,privateJwk}),this.key,ref,1));
  }
  async getSigner(ref: string): Promise<OanSigner> {
    if (!this.key) throw new RuntimeError('vault_locked');
    const generation=this.generation, row=await this.store.load(ref);
    if (!row || !this.key || generation !== this.generation) throw new RuntimeError('vault_locked_or_key_missing');
    const value=JSON.parse(openBlob(row.ciphertext,this.key,ref,row.generation));
    const signer=await createJwkOanSigner(value.method,value.privateJwk);
    const check=() => { if (!this.key || generation !== this.generation) throw new RuntimeError('vault_locked'); };
    return {keyId:signer.keyId,algorithm:'Ed25519',async publicKey(){check();return signer.publicKey();},async signPreparedInput(bytes){check();return signer.signPreparedInput(bytes);}};
  }
}
