// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { verifyPinnedRootPackage, type PinnedRootAnchor } from '@openagenet/oan-sdk-ts';
import type { EvidenceVerifier } from './index.js';
import type { IdentityVerificationReport } from '@openagenet/oan-sdk-ts/protocol-types';

/** Runtime bridge for the SDK's public registration evidence verifier. */
export class PinnedRootEvidenceVerifier implements EvidenceVerifier {
  constructor(private readonly anchor: PinnedRootAnchor, private readonly observedAt: string, private readonly maxAgeMs = 86_400_000) {}
  async verifyRegistration(input: { didDocument: unknown; registrationVc?: unknown; resourcePackage?: unknown; trustAnchor: { mode: 'pinned-root' | 'governance-verified'; rootDid: string }; expectedResourceDid: string }): Promise<IdentityVerificationReport> {
    if (input.trustAnchor.mode !== 'pinned-root' || input.trustAnchor.rootDid !== this.anchor.rootDid || !input.resourcePackage) {
      return { valid: false, checks: [{ name: 'registration_trust', status: 'failed', code: 'pinned_root_evidence_required' }] };
    }
    try {
      const pkg = input.resourcePackage as Parameters<typeof verifyPinnedRootPackage>[0]['resourcePackage'];
      if (JSON.stringify(input.didDocument) !== JSON.stringify(pkg.didDocument)) throw new Error('document_binding_mismatch');
      await verifyPinnedRootPackage({ resourcePackage: pkg, expectedDid: input.expectedResourceDid, anchor: this.anchor, observedAt: this.observedAt, maxAgeMs: this.maxAgeMs });
      return { valid: true, checks: [{ name: 'registration_trust', status: 'passed' }, { name: 'documentBinding', status: 'passed' }] };
    } catch { return { valid: false, checks: [{ name: 'registration_trust', status: 'failed', code: 'registration_evidence_invalid' }] };
    }
  }
}
