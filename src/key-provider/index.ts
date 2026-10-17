// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { OanSigner } from '@openagenet/oan-sdk-ts';
/** Trusted Host SPI, not an agent/plugin API. Implementations retain private keys. */
export interface KeyProvider {
  readonly id: string;
  getSigner(keyRef: string): Promise<OanSigner>;
}
export interface KeyDescriptor {
  keyRef: string;
  verificationMethodId: string;
  algorithm: 'Ed25519';
  exportable: boolean;
}

/** Production provider lifecycle; unsupported operations must fail explicitly. */
export interface ProviderLifecycle {
  lock(): Promise<void>;
  unlock(): Promise<void>;
  close(): Promise<void>;
}

export interface SigningKeyResolver {
  resolve(keyRef: string, purpose: string): Promise<OanSigner>;
}
