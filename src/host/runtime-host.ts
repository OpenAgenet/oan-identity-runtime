// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { createHash } from 'node:crypto';
import { base64url, compactVerify, importJWK } from 'jose';
import type { OanSigner } from '@openagenet/oan-sdk-ts';
import type { SignedMessage } from '../runtime.js';
import type { ReplayStore, SessionRecord } from '../session/index.js';
import type { VerifiedPeer } from '../session/handshake.js';
import type { HandshakeMessage, HandshakeScope } from '../session/handshake.js';
import { digestJson, verifyPinnedMessage } from '../verification/index.js';
import { RuntimeError } from '../errors.js';
import { canonicalJson } from '@openagenet/oan-sdk-ts';

export interface RuntimeHostSession extends SessionRecord {
  binding: { serviceRef: string; protocol: 'a2a' | 'mcp' | 'http'; protocolVersion: string };
}
export interface RuntimeHostSessionProof { scope: HandshakeScope; transcript: [HandshakeMessage, HandshakeMessage, HandshakeMessage, HandshakeMessage] }

/**
 * The network-facing host implementation used by the Ubuntu reference runner.
 * It deliberately contains no HTTP listener: Gateway and Sidecar are the only
 * network listeners, while this class is reachable through authenticated local
 * IPC. A request is accepted only when its signed message, pinned peer key,
 * session scope and durable replay store all agree.
 */
export class RuntimeHostVerifier {
  private readonly sessions = new Map<string, RuntimeHostSession>();
  private readonly verifiedRequests = new Map<string, { peerDid: string; payloadDigest: string; expiresAt: number }>();
  constructor(
    readonly localDid: string,
    readonly signer: OanSigner,
    readonly resolvePeer: (did: string) => Promise<VerifiedPeer>,
    readonly replay: ReplayStore,
  ) {}

  async addVerifiedSession(proof: RuntimeHostSessionProof): Promise<RuntimeHostSession> {
    const { scope, transcript } = structuredClone(proof);
    if (!Array.isArray(transcript) || transcript.length !== 4 || ![scope.initiatorDid, scope.responderDid].includes(this.localDid) || scope.initiatorDid === scope.responderDid) throw new RuntimeError('session_transcript_unverified');
    const kinds = ['client-hello', 'server-proof', 'client-proof', 'session-confirmed'];
    const first = transcript[0]?.body;
    if (!first?.sessionId || !first.nonceA || first.nonceB !== '' || first.previousDigest !== '' || Date.parse(first.expiresAt) <= Date.now() || Date.parse(first.expiresAt) - Date.parse(first.createdAt) > 60000) throw new RuntimeError('session_transcript_unverified');
    for (let index = 0; index < 4; index++) {
      const item = transcript[index], body = item?.body;
      const signerDid = index % 2 === 0 ? scope.initiatorDid : scope.responderDid;
      const peer = await this.resolvePeer(signerDid);
      if (peer.did !== signerDid || peer.validUntil <= Date.parse(first.expiresAt) || (signerDid === this.localDid && (this.signer.keyId !== peer.verificationMethod || (await this.signer.publicKey()).x !== peer.publicKeyJwk.x))) throw new RuntimeError('session_transcript_unverified');
      if (!body || body.kind !== kinds[index] || body.profile !== 'oan-session-v1' || body.sessionId !== first.sessionId || body.nonceA !== first.nonceA || body.createdAt !== first.createdAt || body.expiresAt !== first.expiresAt || Object.keys(scope).some(key => body[key as keyof HandshakeScope] !== scope[key as keyof HandshakeScope]) || (index === 1 && !body.nonceB) || (index > 0 && (body.nonceB !== transcript[1].body.nonceB || body.previousDigest !== await digestJson(transcript[index - 1])))) throw new RuntimeError('session_transcript_unverified');
      try {
        const verified = await compactVerify(item.jws, await importJWK(peer.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
        if (verified.protectedHeader.kid !== peer.verificationMethod || verified.protectedHeader.typ !== 'oan-session-v1+jws' || !Buffer.from(verified.payload).equals(Buffer.from(canonicalJson(body)))) throw new Error();
      } catch { throw new RuntimeError('session_transcript_unverified'); }
    }
    const other = this.localDid === scope.initiatorDid ? scope.responderDid : scope.initiatorDid;
    const session: RuntimeHostSession = { id: first.sessionId, localDid: this.localDid, peerDid: other, state: 'authenticated', expiresAt: first.expiresAt, binding: { serviceRef: scope.serviceRef, protocol: scope.protocol, protocolVersion: scope.protocolVersion } };
    this.sessions.set(session.id, session);
    return structuredClone(session);
  }

  async verify(input: { envelope: unknown; audience: string; requestId: string; payloadDigest: string; callbackDid?: string }): Promise<Record<string, unknown>> {
    const envelope = input.envelope as Record<string, unknown>;
    const message = envelope?.message as SignedMessage | undefined;
    const sessionId = typeof envelope?.sessionId === 'string' ? envelope.sessionId : message?.context?.sessionId;
    if (!message || !sessionId || message.context.audienceDid !== this.localDid || input.audience !== this.localDid || envelope.targetResourceDid !== this.localDid) throw new RuntimeError('message_binding_mismatch');
    const session = this.sessions.get(sessionId);
    if (!session || Date.parse(session.expiresAt) <= Date.now() || session.peerDid !== message.context.senderDid || session.binding.protocol !== message.context.protocol || session.binding.protocolVersion !== message.protocolVersion || session.binding.serviceRef !== message.serviceRef || message.context.purpose !== 'request') throw new RuntimeError('session_not_authenticated');
    const payload = message.payload as Record<string, unknown>;
    if (payload?.rawBodyDigest !== input.payloadDigest) throw new RuntimeError('payload_digest_mismatch');
    const peer = await this.resolvePeer(message.context.senderDid);
    await verifyPinnedMessage(message, {
      senderDid: message.context.senderDid, audienceDid: this.localDid,
      verificationMethod: peer.verificationMethod, publicKeyJwk: peer.publicKeyJwk,
      serviceRef: session.binding.serviceRef, protocolVersion: session.binding.protocolVersion,
      operation: message.operation, requestDigest: message.requestDigest,
      sessionId, requestId: input.requestId, purpose: message.context.purpose,
      protocol: message.context.protocol, replay: this.replay,
    });
    this.verifiedRequests.set(input.requestId, { peerDid: message.context.senderDid, payloadDigest: input.payloadDigest, expiresAt: Math.min(Date.parse(message.context.expiresAt), Date.parse(session.expiresAt)) });
    return {
      subjectDid: message.context.senderDid, audienceDid: this.localDid,
      requestId: input.requestId, payloadDigest: input.payloadDigest,
      callbackDid: input.callbackDid, responseSigningSupported: true,
    };
  }

  async sign(intent: unknown): Promise<unknown> {
    if (!intent || typeof intent !== 'object' || Array.isArray(intent)) throw new RuntimeError('invalid_response_intent');
    const fields = intent as Record<string, unknown>;
    if (!['gateway-response', 'sidecar-response'].includes(String(fields.kind)) || typeof fields.requestId !== 'string' || !fields.requestId || !/^sha256:[0-9a-f]{64}$/.test(String(fields.payloadDigest)) || !/^sha256:[0-9a-f]{64}$/.test(String(fields.requestPayloadDigest)) || fields.targetResourceDid !== this.localDid || typeof fields.audienceDid !== 'string' || !fields.audienceDid || !Number.isInteger(fields.status) || Number(fields.status) < 100 || Number(fields.status) > 599) throw new RuntimeError('invalid_response_intent');
    const verified = this.verifiedRequests.get(fields.requestId as string);
    if (!verified || verified.expiresAt <= Date.now() || verified.peerDid !== fields.audienceDid || verified.payloadDigest !== fields.requestPayloadDigest) throw new RuntimeError('response_request_unverified');
    this.verifiedRequests.delete(fields.requestId as string);
    const envelope = { ...(intent as Record<string, unknown>), senderDid: this.localDid, verificationMethod: this.signer.keyId };
    const protectedHeader = base64url.encode(JSON.stringify({ alg: 'EdDSA', kid: this.signer.keyId, typ: 'oan-native-response+jws' }));
    const payload = base64url.encode(canonicalJson(envelope));
    const value = `${protectedHeader}.${payload}.${base64url.encode(await this.signer.signPreparedInput(new TextEncoder().encode(`${protectedHeader}.${payload}`)))}`;
    return { envelope, signature: { verificationMethod: this.signer.keyId, value } };
  }
}

export function nativeResponseDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

/** Verify the exact wire response bytes and all request correlation fields. */
export async function verifyNativeResponseProof(input: {
  encodedProof: string; responseBody: Uint8Array; status: number;
  expected: { kind: 'gateway-response' | 'sidecar-response'; senderDid: string; audienceDid: string; targetResourceDid: string; requestId: string; requestPayloadDigest: string };
  resolvePeer: (did: string) => Promise<VerifiedPeer>;
}): Promise<Record<string, unknown>> {
  let signed: any;
  try { signed = JSON.parse(Buffer.from(input.encodedProof, 'base64url').toString('utf8')); }
  catch { throw new RuntimeError('response_proof_invalid'); }
  const envelope = signed?.envelope as Record<string, unknown> | undefined;
  const signature = signed?.signature;
  const peer = await input.resolvePeer(input.expected.senderDid);
  const payloadDigest = `sha256:${createHash('sha256').update(input.responseBody).digest('hex')}`;
  if (!envelope || envelope.kind !== input.expected.kind || envelope.senderDid !== input.expected.senderDid || envelope.audienceDid !== input.expected.audienceDid || envelope.targetResourceDid !== input.expected.targetResourceDid || envelope.requestId !== input.expected.requestId || envelope.requestPayloadDigest !== input.expected.requestPayloadDigest || envelope.payloadDigest !== payloadDigest || envelope.status !== input.status || signature?.verificationMethod !== peer.verificationMethod || typeof signature?.value !== 'string') throw new RuntimeError('response_proof_binding_invalid');
  try {
    const verified = await compactVerify(signature.value, await importJWK(peer.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
    if (verified.protectedHeader.kid !== peer.verificationMethod || verified.protectedHeader.typ !== 'oan-native-response+jws' || !Buffer.from(verified.payload).equals(Buffer.from(canonicalJson(envelope), 'utf8'))) throw new Error();
  } catch { throw new RuntimeError('response_proof_signature_invalid'); }
  return structuredClone(envelope);
}
