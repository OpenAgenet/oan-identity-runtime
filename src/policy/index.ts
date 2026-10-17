// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { RuntimeError } from '../errors.js';
export type MessagePurpose = 'request' | 'response' | 'challenge' | 'event';
export interface SignIntent {
  identityRef: string;
  audienceDid: string;
  purpose: MessagePurpose;
  protocol: 'http' | 'mcp' | 'a2a';
  protocolVersion: string;
  operation: string;
  serviceRef: string;
  requestDigest?: string;
  stream?: { taskId: string; sequence: number; previousDigest: string; state: 'partial' | 'complete' | 'cancelled' };
  sessionId: string;
  requestId: string;
  payload: unknown;
}
/** Authenticated host transport supplies both IDs; neither comes from request JSON. */
export interface CallerContext { callerId: string; tenantId?: string }
export interface PolicyRule {
  callerId: string;
  tenantId?: string;
  identityRef: string;
  audienceDid: string;
  purpose: MessagePurpose;
  protocol: SignIntent['protocol'];
  operation: string;
}
/** Async policy port allows trusted approval and object-level rules later. */
export interface IntentPolicy {
  authorize(caller: CallerContext, intent: SignIntent): Promise<void>;
  canAccessIdentity(caller: CallerContext, identityRef: string): boolean;
}
export class PolicyEngine implements IntentPolicy {
  private readonly rules: PolicyRule[];
  constructor(rules: readonly PolicyRule[] = []) { this.rules = structuredClone([...rules]); }
  canAccessIdentity(caller: CallerContext, identityRef: string): boolean {
    return this.rules.some(r => r.callerId === caller.callerId && r.tenantId === caller.tenantId && r.identityRef === identityRef);
  }
  async authorize(caller: CallerContext, intent: SignIntent): Promise<void> {
    if (!this.rules.some(r => r.callerId === caller.callerId && r.tenantId === caller.tenantId && r.identityRef === intent.identityRef && r.audienceDid === intent.audienceDid && r.purpose === intent.purpose && r.protocol === intent.protocol && r.operation === intent.operation)) {
      throw new RuntimeError('policy_denied');
    }
  }
}
