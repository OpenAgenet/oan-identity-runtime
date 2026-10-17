// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { RuntimeError } from '../errors.js';
export type PublicationState = 'candidate' | 'submitted' | 'uncertain' | 'registered' | 'rejected';
/** Transport uncertainty retains the candidate and never generates another DID. */
export interface PublicationAttempt {
  attemptId: string; resourceDid: string; candidateDigest: string;
  idempotencyKey: string; state: PublicationState;
}
export interface ConfirmedPublicationEvidence {
  resourceDid: string; documentDigest: string; packageVersion: string;
  registrarVersion: string; source: string; evidenceRef: string;
}
export type PublicationObservation =
  | { kind: 'unknown' }
  | { kind: 'rejected-before-acceptance' }
  | { kind: 'confirmed'; evidence: ConfirmedPublicationEvidence };
/** Only a trusted evidence verifier supplies confirmed observations. */
export function observePublication(attempt: PublicationAttempt, observation: PublicationObservation): PublicationAttempt {
  if (!['submitted', 'uncertain'].includes(attempt.state)) throw new RuntimeError('invalid_publication_transition');
  if (observation.kind === 'unknown') return { ...attempt, state: 'uncertain' };
  if (observation.kind === 'rejected-before-acceptance') {
    if (attempt.state === 'uncertain') throw new RuntimeError('publication_reconciliation_required');
    return { ...attempt, state: 'rejected' };
  }
  const proof = observation.evidence;
  if (proof.resourceDid !== attempt.resourceDid || proof.documentDigest !== attempt.candidateDigest || !proof.packageVersion || !proof.registrarVersion || !proof.source || !proof.evidenceRef) throw new RuntimeError('publication_evidence_binding_mismatch');
  return { ...attempt, state: 'registered' };
}
export interface PublicationReconciler { reconcile(attempt: PublicationAttempt): Promise<PublicationAttempt> }
