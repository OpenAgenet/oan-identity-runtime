// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { validateMessageBinding } from '../profiles/message.js';
import { compactVerify, importJWK } from 'jose';
import { createHash } from 'node:crypto';
import { canonicalJson } from '@openagenet/oan-sdk-ts';
import type { SignedMessage } from '../runtime.js';
import type { ReplayStore } from '../session/index.js';
import { RuntimeError } from '../errors.js';
export async function digestJson(value: unknown): Promise<string> {
  assertJsonValue(value);
  const encoded = canonicalJson(value);
  if (typeof encoded !== 'string' || JSON.stringify(value) === undefined) throw new RuntimeError('invalid_json_payload');
  return `sha256:${createHash('sha256').update(encoded, 'utf8').digest('hex')}`;
}
/** Reject lossy JS values before canonicalization (undefined, NaN, sparse arrays, etc.). */
function assertJsonValue(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (typeof value !== 'object' || seen.has(value)) throw new RuntimeError('invalid_json_payload');
  seen.add(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new RuntimeError('invalid_json_payload');
      assertJsonValue(value[i], seen);
    }
  } else {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new RuntimeError('invalid_json_payload');
    for (const entry of Object.values(value)) assertJsonValue(entry, seen);
  }
  seen.delete(value);
}
/** Cryptographic check with an externally pinned key. Does NOT establish registration trust. */
export async function verifyPinnedMessage(message: SignedMessage, options: {
  senderDid: string; audienceDid: string; verificationMethod: string; publicKeyJwk: JsonWebKey;
  serviceRef: string; protocolVersion: string; operation: string; requestDigest?: string;
  sessionId: string; requestId: string; purpose: SignedMessage['context']['purpose'];
  protocol: SignedMessage['context']['protocol']; replay: ReplayStore; now?: number;
}): Promise<{ signatureValid: true; registrationTrust: 'not_checked' }> {
  const {replay,...binding}=options;
  options={...structuredClone(binding),replay};
  const snapshot = structuredClone(message);
  const { context, operation, payload, signature, serviceRef, protocolVersion, requestDigest, stream } = snapshot;
  validateMessageBinding({ purpose: context.purpose, serviceRef, protocolVersion, requestDigest, stream });
  const now = options.now ?? Date.now();
  const created = Date.parse(context.createdAt), expires = Date.parse(context.expiresAt);
  if (context.profile !== 'oan-message-v1' || context.senderDid !== options.senderDid || context.audienceDid !== options.audienceDid || context.sessionId !== options.sessionId || context.requestId !== options.requestId || context.purpose !== options.purpose || context.protocol !== options.protocol || signature.verificationMethod !== options.verificationMethod || protocolVersion !== options.protocolVersion || serviceRef !== options.serviceRef || requestDigest !== options.requestDigest || operation !== options.operation || !operation || !context.messageId || !context.nonce) throw new RuntimeError('message_binding_mismatch');
  if (!Number.isFinite(now) || !Number.isFinite(created) || !Number.isFinite(expires) || created > now + 30000 || expires <= now || expires <= created || expires - created > 60000) throw new RuntimeError('message_time_invalid');
  if (context.payloadDigest !== await digestJson(payload)) throw new RuntimeError('payload_digest_mismatch');
  const key = await importJWK(options.publicKeyJwk, 'EdDSA');
  const bytes = new TextEncoder().encode(canonicalJson({ context, operation, serviceRef, protocolVersion,
    ...(requestDigest ? { requestDigest } : {}), ...(stream ? { stream } : {}), payload }));
  try {
    const verified = await compactVerify(signature.value, key, { algorithms: ['EdDSA'] });
    if (verified.protectedHeader.kid !== options.verificationMethod || verified.protectedHeader.typ !== 'oan-message-v1+jws' || !Buffer.from(bytes).equals(Buffer.from(verified.payload))) throw new Error();
  } catch { throw new RuntimeError('message_signature_invalid'); }
  await options.replay.consume(JSON.stringify([context.senderDid, context.audienceDid, context.purpose, context.sessionId]), context.nonce, expires, now);
  return { signatureValid: true, registrationTrust: 'not_checked' };
}
