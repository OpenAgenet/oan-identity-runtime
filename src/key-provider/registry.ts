// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { OanSigner } from '@openagenet/oan-sdk-ts';
import type { KeyProvider, SigningKeyResolver } from './index.js';
import { RuntimeError } from '../errors.js';
/** A provider selector is internal host configuration, never part of a public identity. */
export interface ManagedKeyRef { id: string; providerId: string; providerKeyId: string; purposes: readonly string[] }
export class KeyProviderRegistry implements SigningKeyResolver {
  private readonly providers = new Map<string, KeyProvider>();
  private readonly refs = new Map<string, ManagedKeyRef>();
  constructor(providers: readonly KeyProvider[], refs: readonly ManagedKeyRef[] = []) {
    for (const ref of refs) {
      if (this.refs.has(ref.id)) throw new RuntimeError('duplicate_key_reference');
      this.refs.set(ref.id, structuredClone(ref));
    }
    for (const provider of providers) {
      if (this.providers.has(provider.id)) throw new RuntimeError('duplicate_key_provider');
      this.providers.set(provider.id, provider);
    }
  }
  async resolve(keyRef: string, purpose: string): Promise<OanSigner> {
    const ref = this.refs.get(keyRef);
    if (!ref) throw new RuntimeError('key_reference_not_found');
    return this.signerFor(ref, purpose);
  }
  async signerFor(ref: ManagedKeyRef, purpose: string): Promise<OanSigner> {
    if (!ref.purposes.includes(purpose)) throw new RuntimeError('key_purpose_denied');
    const provider = this.providers.get(ref.providerId);
    if (!provider) throw new RuntimeError('key_provider_unavailable');
    return provider.getSigner(ref.providerKeyId);
  }
}
