// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { IdentityVerificationReport } from '@openagenet/oan-sdk-ts/protocol-types';
/** Host-supplied trust verifier; absence must fail closed. */
export interface EvidenceVerifier {
  verifyRegistration(input: { didDocument: unknown; registrationVc?: unknown; resourcePackage?: unknown; trustAnchor: { mode: 'pinned-root' | 'governance-verified'; rootDid: string }; expectedResourceDid: string }): Promise<IdentityVerificationReport>;
}
export interface EvidenceRecord { id: string; source: string; digest: string; fetchedAt: string; report: IdentityVerificationReport }

/** Do not collapse signature success, stale status and missing governance into one bool. */
export interface EvidenceCheck {
  name: 'signature' | 'documentBinding' | 'registrationEvidence' | 'registrationStatus' | 'governance' | 'controllerBinding' | 'instanceBinding';
  status: 'valid' | 'invalid' | 'unknown' | 'not_applicable';
  source?: string; observedAt?: string; fetchedAt?: string; maxAgeMs?: number;
}
