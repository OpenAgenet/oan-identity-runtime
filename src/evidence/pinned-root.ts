// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { verifyIdentityEvidence, type IdentityEvidencePolicy } from '@openagenet/oan-sdk-ts';
import type { EvidenceVerifier } from './index.js';
import type { IdentityVerificationReport, ResourcePackage, DidDocument } from '@openagenet/oan-sdk-ts/protocol-types';
/** Host-pinned trust source and observation time cannot be replaced by peer claims. */
export class PinnedRootEvidenceVerifier implements EvidenceVerifier {
  private readonly policy: IdentityEvidencePolicy;
  constructor(anchor: IdentityEvidencePolicy['anchor'], observedAt: string, maxAgeMs=86_400_000,
    options: Pick<IdentityEvidencePolicy,'registrar'|'requirePrivateVc'|'now'> = {}) {
    this.policy=structuredClone({...options,anchor,observedAt,maxAgeMs,registrar:undefined});
    if(options.registrar){const {documentLoader,...config}=options.registrar;this.policy.registrar={...structuredClone(config),documentLoader};}
  }
  async verifyRegistration(input: Parameters<EvidenceVerifier['verifyRegistration']>[0]): Promise<IdentityVerificationReport> {
    if(input.trustAnchor.mode!=='pinned-root' || input.trustAnchor.rootDid!==this.policy.anchor.rootDid)
      return {valid:false,checks:[{name:'registrationTrust',status:'failed',code:'pinned_root_evidence_required'}]};
    try {
      return await verifyIdentityEvidence({expectedDid:input.expectedResourceDid,didDocument:input.didDocument as DidDocument,
        resourcePackage:input.resourcePackage as ResourcePackage|undefined,registrationVc:input.registrationVc},this.policy);
    } catch {return {valid:false,checks:[{name:'registrationTrust',status:'failed',code:'registration_evidence_invalid'}]};}
  }
}
