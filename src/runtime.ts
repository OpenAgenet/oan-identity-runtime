// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { validateMessageBinding } from './profiles/message.js';
import { base64url } from 'jose';
import { randomUUID } from 'node:crypto';
import { canonicalJson, parseDidOan, asDataIntegritySigner } from '@openagenet/oan-sdk-ts';
import type { IdentityMessageContext } from '@openagenet/oan-sdk-ts/protocol-types';
import { publicIdentity, type IdentityRepository } from './catalog/index.js';
import type { SigningKeyResolver } from './key-provider/index.js';
import type { CallerContext, IntentPolicy, SignIntent } from './policy/index.js';
import type { SessionManager } from './session/index.js';
import type { AuditSink } from './audit/index.js';
import { RuntimeError } from './errors.js';
import { digestJson } from './verification/index.js';
export interface SignedMessage {
  context: IdentityMessageContext;
  operation: string;
  serviceRef: string;
  protocolVersion: string;
  requestDigest?: string;
  stream?: SignIntent['stream'];
  payload: unknown;
  signature: { verificationMethod: string; value: string };
}
/** In-process facade. Not yet a network or MCP server. */
export class IdentityRuntime {
  constructor(private readonly deps: { catalog: IdentityRepository; keys: SigningKeyResolver; policy: IntentPolicy; sessions: SessionManager; audit: AuditSink }) {}
  async listIdentities(caller: CallerContext) {
    return (await this.deps.catalog.list()).filter(record => this.deps.policy.canAccessIdentity(caller, record.id)).map(publicIdentity);
  }
  async signIntent(caller: CallerContext, input: SignIntent): Promise<SignedMessage> {
    // Snapshot before any await: policy and signature must cover the same object.
    const intent = structuredClone(input);
    const authenticatedCaller = structuredClone(caller);
    try {
      await this.deps.policy.authorize(authenticatedCaller, structuredClone(intent));
      const identity = await this.deps.catalog.get(intent.identityRef);
      if (identity.status !== 'registered') throw new RuntimeError('identity_not_ready_for_business_signing');
      if (intent.purpose === 'challenge') throw new RuntimeError('unsupported:session_handshake');
      parseDidOan(identity.did); parseDidOan(intent.audienceDid);
      const session = structuredClone(await (this.deps.sessions.requireAuthenticatedForCaller
        ? this.deps.sessions.requireAuthenticatedForCaller(authenticatedCaller,intent.sessionId,identity.did,intent.audienceDid)
        : this.deps.sessions.requireAuthenticated(intent.sessionId, identity.did, intent.audienceDid)));
      if (session.binding && (session.binding.serviceRef !== intent.serviceRef || session.binding.protocol !== intent.protocol || session.binding.protocolVersion !== intent.protocolVersion)) throw new RuntimeError('session_scope_mismatch');
      const expiry = Date.parse(session.expiresAt);
      const now = Date.now();
      if (session.id !== intent.sessionId || session.state !== 'authenticated' || session.localDid !== identity.did || session.peerDid !== intent.audienceDid || !Number.isFinite(expiry) || expiry <= now) throw new RuntimeError('session_not_authenticated');
      const context: IdentityMessageContext = {
        profile: 'oan-message-v1', senderDid: identity.did, audienceDid: intent.audienceDid,
        purpose: intent.purpose, protocol: intent.protocol, sessionId: intent.sessionId,
        messageId: randomUUID(), requestId: intent.requestId, nonce: randomUUID(),
        createdAt: new Date(now).toISOString(), expiresAt: new Date(Math.min(expiry, now + 60000)).toISOString(),
        payloadDigest: await digestJson(intent.payload),
      };
      if (!intent.operation || !intent.requestId) throw new RuntimeError('invalid_sign_intent');
      const signer = await this.deps.keys.resolve(identity.keyRef, intent.purpose);
      const method = identity.didDocument.verificationMethod?.find(m => m.id === identity.verificationMethodId);
      const publicJwk = await signer.publicKey();
      if (identity.didDocument.id !== identity.did || method?.controller !== identity.did || method.publicKeyJwk?.x !== publicJwk.x || method.publicKeyJwk?.crv !== publicJwk.crv || method.publicKeyJwk?.kty !== publicJwk.kty || !identity.didDocument.authentication?.includes(identity.verificationMethodId)) throw new RuntimeError('identity_key_binding_mismatch');
      const checkedSigner = await asDataIntegritySigner(signer, identity.verificationMethodId);
      validateMessageBinding(intent);
      const signed = { context, operation: intent.operation, serviceRef: intent.serviceRef, protocolVersion: intent.protocolVersion,
        ...(intent.requestDigest ? { requestDigest: intent.requestDigest } : {}),
        ...(intent.stream ? { stream: intent.stream } : {}), payload: intent.payload };

      const bytes = new TextEncoder().encode(canonicalJson(signed));
      // jose verifies the compact JWS; the trusted external signer retains its key.
      const protectedHeader = base64url.encode(JSON.stringify({ alg: 'EdDSA', kid: signer.keyId, typ: 'oan-message-v1+jws' }));
      const signingInput = protectedHeader + '.' + base64url.encode(bytes);
      const value = signingInput + '.' + base64url.encode(await checkedSigner.sign({ data: new TextEncoder().encode(signingInput) }));
      await this.deps.audit.append({ timestamp: new Date().toISOString(), action: 'sign_intent', outcome: 'allowed', identityRef: intent.identityRef });
      return { ...signed, signature: { verificationMethod: signer.keyId, value } };
    } catch (error) {
      await this.deps.audit.append({ timestamp: new Date().toISOString(), action: 'sign_intent', outcome: 'denied', identityRef: intent.identityRef, code: error instanceof RuntimeError ? error.code : 'signing_failed' });
      throw error;
    }
  }
}
