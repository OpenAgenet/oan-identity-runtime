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
    readonly scope?: { runId: string; tenantId: string },
  ) {}

  private prune(): void {
    const now = Date.now();
    for (const [id, session] of this.sessions) if (Date.parse(session.expiresAt) <= now) this.sessions.delete(id);
    for (const [id, request] of this.verifiedRequests) if (request.expiresAt <= now) this.verifiedRequests.delete(id);
  }

  async addVerifiedSession(proof: RuntimeHostSessionProof): Promise<RuntimeHostSession> {
    this.prune();
    const { scope, transcript } = structuredClone(proof);
    if (!Array.isArray(transcript) || transcript.length !== 4 || ![scope.initiatorDid, scope.responderDid].includes(this.localDid) || scope.initiatorDid === scope.responderDid) throw new RuntimeError('session_transcript_unverified');
    const kinds = ['client-hello', 'server-proof', 'client-proof', 'session-confirmed'];
    const first = transcript[0]?.body;
    const created = Date.parse(first?.createdAt), expires = Date.parse(first?.expiresAt), now = Date.now();
    if (!first?.sessionId || !first.nonceA || first.nonceB !== '' || first.previousDigest !== '' || !Number.isFinite(created) || !Number.isFinite(expires)
      || created > now + 30000 || expires <= now || expires <= created || expires - created > 60000) throw new RuntimeError('session_transcript_unverified');
    for (let index = 0; index < 4; index++) {
      const item = transcript[index], body = item?.body;
      const signerDid = index % 2 === 0 ? scope.initiatorDid : scope.responderDid;
      const peer = await this.resolvePeer(signerDid);
      if (peer.did !== signerDid || !Number.isFinite(peer.validUntil) || peer.validUntil <= expires || (signerDid === this.localDid && (this.signer.keyId !== peer.verificationMethod || (await this.signer.publicKey()).x !== peer.publicKeyJwk.x))) throw new RuntimeError('session_transcript_unverified');
      if (!body || body.kind !== kinds[index] || body.profile !== 'oan-session-v1' || body.sessionId !== first.sessionId || body.nonceA !== first.nonceA || body.createdAt !== first.createdAt || body.expiresAt !== first.expiresAt || Object.keys(scope).some(key => body[key as keyof HandshakeScope] !== scope[key as keyof HandshakeScope]) || (index === 1 && !body.nonceB) || (index > 0 && (body.nonceB !== transcript[1].body.nonceB || body.previousDigest !== await digestJson(transcript[index - 1])))) throw new RuntimeError('session_transcript_unverified');
      try {
        const verified = await compactVerify(item.jws, await importJWK(peer.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
        if (verified.protectedHeader.kid !== peer.verificationMethod || verified.protectedHeader.typ !== 'oan-session-v1+jws' || !Buffer.from(verified.payload).equals(Buffer.from(canonicalJson(body)))) throw new Error();
      } catch { throw new RuntimeError('session_transcript_unverified'); }
    }
    const other = this.localDid === scope.initiatorDid ? scope.responderDid : scope.initiatorDid;
    const session: RuntimeHostSession = { id: first.sessionId, localDid: this.localDid, peerDid: other, state: 'authenticated', expiresAt: first.expiresAt, binding: { serviceRef: scope.serviceRef, protocol: scope.protocol, protocolVersion: scope.protocolVersion } };
    if (!this.sessions.has(session.id) && this.sessions.size >= 1000) throw new RuntimeError('session_capacity_exceeded');
    this.sessions.set(session.id, session);
    return structuredClone(session);
  }

  async verify(input: { envelope: unknown; audience: string; requestId: string; payloadDigest: string; callbackDid?: string }): Promise<Record<string, unknown>> {
    this.prune();
    if (this.verifiedRequests.size >= 10000) throw new RuntimeError('request_capacity_exceeded');
    const envelope = input.envelope as Record<string, unknown>;
    const message = envelope?.message as SignedMessage | undefined;
    const sessionId = typeof envelope?.sessionId === 'string' ? envelope.sessionId : message?.context?.sessionId;
    if (!message || !sessionId || message.context.audienceDid !== this.localDid || input.audience !== this.localDid || envelope.targetResourceDid !== this.localDid) throw new RuntimeError('message_binding_mismatch');
    const session = this.sessions.get(sessionId);
    if (!session || Date.parse(session.expiresAt) <= Date.now() || session.peerDid !== message.context.senderDid || session.binding.protocol !== message.context.protocol || session.binding.protocolVersion !== message.protocolVersion || session.binding.serviceRef !== message.serviceRef || message.context.purpose !== 'request') throw new RuntimeError('session_not_authenticated');
    const payload = message.payload as Record<string, unknown>;
    if (this.scope && (payload?.runId !== this.scope.runId || payload?.tenantId !== this.scope.tenantId || envelope.tenantId !== this.scope.tenantId)) throw new RuntimeError('message_binding_mismatch');
    if (this.scope) {
      const http = payload.httpBinding as Record<string, unknown> | undefined;
      if (!http || typeof http.method !== 'string' || typeof http.target !== 'string' || typeof http.mcpSessionId !== 'string') throw new RuntimeError('http_request_binding_required');
    }
    if (payload?.rawBodyDigest !== input.payloadDigest) throw new RuntimeError('payload_digest_mismatch');
    const peer = await this.resolvePeer(message.context.senderDid);
    if (peer.did !== session.peerDid || !Number.isFinite(peer.validUntil) || peer.validUntil <= Date.now()) throw new RuntimeError('session_evidence_expired');
    await verifyPinnedMessage(message, {
      senderDid: message.context.senderDid, audienceDid: this.localDid,
      verificationMethod: peer.verificationMethod, publicKeyJwk: peer.publicKeyJwk,
      serviceRef: session.binding.serviceRef, protocolVersion: session.binding.protocolVersion,
      operation: message.operation, requestDigest: message.requestDigest,
      sessionId, requestId: input.requestId, purpose: message.context.purpose,
      protocol: message.context.protocol, replay: this.replay,
    });
    const requestKey = JSON.stringify([input.requestId, message.context.senderDid]);
    // Check after asynchronous verification too: a fresh nonce must not replace
    // an in-flight response-signing receipt for the same peer/request ID.
    if (this.verifiedRequests.has(requestKey)) throw new RuntimeError('request_already_in_flight');
    this.verifiedRequests.set(requestKey, { peerDid: message.context.senderDid, payloadDigest: input.payloadDigest, expiresAt: Math.min(Date.parse(message.context.expiresAt), Date.parse(session.expiresAt)) });
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
    this.prune();
    const requestKey = JSON.stringify([fields.requestId, fields.audienceDid]);
    const verified = this.verifiedRequests.get(requestKey);
    if (!verified || verified.expiresAt <= Date.now() || verified.peerDid !== fields.audienceDid || verified.payloadDigest !== fields.requestPayloadDigest) throw new RuntimeError('response_request_unverified');
    this.verifiedRequests.delete(requestKey);
    const envelope = { ...(intent as Record<string, unknown>), senderDid: this.localDid, verificationMethod: this.signer.keyId };
    const protectedHeader = base64url.encode(JSON.stringify({ alg: 'EdDSA', kid: this.signer.keyId, typ: 'oan-native-response+jws' }));
    const payload = base64url.encode(canonicalJson(envelope));
    const value = `${protectedHeader}.${payload}.${base64url.encode(await this.signer.signPreparedInput(new TextEncoder().encode(`${protectedHeader}.${payload}`)))}`;
    return { envelope, signature: { verificationMethod: this.signer.keyId, value } };
  }

  /** Local egress enforcement: only this actor's authenticated session and
   * locally signed request may leave its caller-side Gateway. The receiver
   * still independently verifies the same request and signs its response. */
  async verifyOutbound(input: { envelope: unknown; audience: string; requestId: string; payloadDigest: string }): Promise<Record<string, unknown>> {
    this.prune();
    const envelope = input.envelope as any, message = envelope?.message as SignedMessage;
    const session = this.sessions.get(envelope?.sessionId);
    if (!message || !session || session.localDid !== this.localDid || session.peerDid !== input.audience
      || message.context.senderDid !== this.localDid || message.context.audienceDid !== input.audience
      || envelope.targetResourceDid !== input.audience || message.context.purpose !== 'request'
      || Date.parse(session.expiresAt) <= Date.now() || message.context.protocol !== session.binding.protocol
      || message.serviceRef !== session.binding.serviceRef || message.protocolVersion !== session.binding.protocolVersion
      || (message.payload as any)?.rawBodyDigest !== input.payloadDigest) throw new RuntimeError('message_binding_mismatch');
    const payload = message.payload as any;
    if (this.scope && (payload.runId !== this.scope.runId || payload.tenantId !== this.scope.tenantId || envelope.tenantId !== this.scope.tenantId
      || typeof payload.httpBinding?.method !== 'string' || typeof payload.httpBinding?.target !== 'string' || typeof payload.httpBinding?.mcpSessionId !== 'string')) throw new RuntimeError('message_binding_mismatch');
    const local = await this.resolvePeer(this.localDid);
    await verifyPinnedMessage(message, { senderDid: this.localDid, audienceDid: input.audience, verificationMethod: local.verificationMethod,
      publicKeyJwk: local.publicKeyJwk, serviceRef: session.binding.serviceRef, protocolVersion: session.binding.protocolVersion,
      operation: message.operation, requestDigest: message.requestDigest, sessionId: session.id, requestId: input.requestId,
      purpose: 'request', protocol: message.context.protocol, replay: this.replay });
    return { subjectDid: this.localDid, audienceDid: input.audience, requestId: input.requestId, payloadDigest: input.payloadDigest };
  }
}

export function nativeResponseDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

/** The terminal SSE extension authenticates all original bytes in wire order.
 * Until this check succeeds, streamed events are provisional, never trusted results.
 */
export function splitNativeStreamProof(bytes: Uint8Array): { body: Uint8Array; encodedProof: string } {
  const buffer = Buffer.from(bytes);
  const marker = Buffer.from('\nevent: oan-response-proof\ndata: ', 'utf8');
  const position = buffer.lastIndexOf(marker);
  if (position < 0) throw new RuntimeError('stream_terminal_proof_missing');
  const terminal = buffer.subarray(position + marker.length).toString('utf8');
  if (!/^[A-Za-z0-9_-]+\n\n$/.test(terminal) || buffer.indexOf(marker) !== position) throw new RuntimeError('stream_terminal_proof_invalid');
  return { body: buffer.subarray(0, position), encodedProof: terminal.slice(0, -2) };
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
  if (peer.did !== input.expected.senderDid || !Number.isFinite(peer.validUntil) || peer.validUntil <= Date.now()) throw new RuntimeError('response_peer_evidence_invalid');
  const payloadDigest = `sha256:${createHash('sha256').update(input.responseBody).digest('hex')}`;
  if (!envelope || envelope.kind !== input.expected.kind || envelope.senderDid !== input.expected.senderDid || envelope.audienceDid !== input.expected.audienceDid || envelope.targetResourceDid !== input.expected.targetResourceDid || envelope.requestId !== input.expected.requestId || envelope.requestPayloadDigest !== input.expected.requestPayloadDigest || envelope.payloadDigest !== payloadDigest || envelope.status !== input.status || signature?.verificationMethod !== peer.verificationMethod || typeof signature?.value !== 'string') {
    throw new RuntimeError('response_proof_binding_invalid');
  }
  try {
    const verified = await compactVerify(signature.value, await importJWK(peer.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
    if (verified.protectedHeader.kid !== peer.verificationMethod || verified.protectedHeader.typ !== 'oan-native-response+jws' || !Buffer.from(verified.payload).equals(Buffer.from(canonicalJson(envelope), 'utf8'))) throw new Error();
  } catch { throw new RuntimeError('response_proof_signature_invalid'); }
  return structuredClone(envelope);
}
