// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { OanIdentityRecord } from '@openagenet/oan-sdk-ts';
import type { PublicIdentity } from '../catalog/index.js';

/** Trusted local import only. This contract is not an agent-facing tool. */
export interface IdentityImportBundle {
  identity: OanIdentityRecord | import('@openagenet/oan-sdk-ts/protocol-types').DidOanIdentity;
  didDocument: unknown;
  registrationVc?: unknown;
  sources: Array<{ kind: 'discovery' | 'resource-package'; uri: string; digest?: string }>;
}

export interface CapabilityLease {
  id: string;
  callerId: string;
  tenantId?: string;
  purpose: string;
  audienceDid: string;
  candidateDigest: string;
  identityRef: string;
  operation: 'import' | 'rotate' | 'publish' | 'backup';
  expiresAt: string;
}

/** Host must issue and validate leases internally, never trust caller-supplied claims. */
export interface IdentityHost {
  importIdentity(bundle: IdentityImportBundle, leaseId: string): Promise<PublicIdentity>;
}
