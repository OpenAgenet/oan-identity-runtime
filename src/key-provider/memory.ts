// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { createJwkOanSigner, type OanSigner } from '@openagenet/oan-sdk-ts';
import { RuntimeError } from '../errors.js';
import type { KeyProvider } from './index.js';
/** Development/test provider. Keys are non-extractable CryptoKeys, not persistent. */
export class MemoryKeyProvider implements KeyProvider {
  readonly id = 'memory';
  private readonly signers = new Map<string, OanSigner>();
  async importJwk(keyRef: string, method: string, privateJwk: JsonWebKey): Promise<void> {
    if (this.signers.has(keyRef)) throw new RuntimeError('key_already_exists');
    this.signers.set(keyRef, await createJwkOanSigner(method, privateJwk));
  }
  async getSigner(keyRef: string): Promise<OanSigner> {
    const signer = this.signers.get(keyRef);
    if (!signer) throw new RuntimeError('key_not_found');
    return signer;
  }
}
