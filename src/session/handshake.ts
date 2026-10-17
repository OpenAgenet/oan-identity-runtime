// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { randomUUID } from 'node:crypto';
import { canonicalJson, type OanSigner } from '@openagenet/oan-sdk-ts';
import { base64url, compactVerify, importJWK } from 'jose';
import type { SessionManager, SessionRecord } from './index.js';
import { digestJson } from '../verification/index.js';
import { RuntimeError } from '../errors.js';

export interface HandshakeScope {
  initiatorDid: string; responderDid: string; serviceRef: string;
  protocol: 'mcp' | 'a2a' | 'http'; protocolVersion: string;
}
export interface HandshakeBody extends HandshakeScope {
  profile: 'oan-session-v1'; kind: 'client-hello' | 'server-proof' | 'client-proof' | 'session-confirmed';
  sessionId: string; nonceA: string; nonceB: string; previousDigest: string;
  createdAt: string; expiresAt: string;
}
export interface HandshakeMessage { body: HandshakeBody; jws: string }
export interface VerifiedPeer {
  did: string; verificationMethod: string; publicKeyJwk: JsonWebKey; validUntil: number;
}
type State = { role: 'initiator' | 'responder'; scope: HandshakeScope; last: HandshakeMessage; stage: 'hello' | 'server' | 'client' | 'completed'; acceptedClient?: string; confirmation?: HandshakeMessage };

/** One trusted local host owns an instance. Peer keys MUST come from verified evidence.
 * Final confirmation can be resent for the exact client proof until session expiry.
 * Sessions are intentionally invalidated on host restart; replay storage is independent.
 */
export class MutualHandshake implements SessionManager {
  private readonly states = new Map<string, State>();
  constructor(private readonly localDid: string, private readonly signer: OanSigner,
    private readonly resolvePeer: (did: string) => Promise<VerifiedPeer>, private readonly maxSessions = 1000) {}
  private prune() {
    for (const [id, s] of this.states) if (Date.parse(s.last.body.expiresAt) <= Date.now()) this.states.delete(id);
    if (this.states.size >= this.maxSessions) throw new RuntimeError('session_capacity_exceeded');
  }
  private async signed(body: HandshakeBody): Promise<HandshakeMessage> {
    const peerDid = this.localDid === body.initiatorDid ? body.responderDid : body.initiatorDid;
    const own = await this.resolvePeer(this.localDid), peer = await this.resolvePeer(peerDid);
    if (this.signer.keyId !== own.verificationMethod || (await this.signer.publicKey()).x !== own.publicKeyJwk.x || Math.min(own.validUntil, peer.validUntil) <= Date.parse(body.expiresAt)) throw new RuntimeError('handshake_key_or_evidence_invalid');
    const header = base64url.encode(JSON.stringify({ alg: 'EdDSA', kid: this.signer.keyId, typ: 'oan-session-v1+jws' }));
    const input = `${header}.${base64url.encode(canonicalJson(body))}`;
    return { body, jws: `${input}.${base64url.encode(await this.signer.signPreparedInput(new TextEncoder().encode(input)))}` };
  }
  private async check(message: HandshakeMessage, scope: HandshakeScope, kind: HandshakeBody['kind'], expected: string): Promise<void> {
    if (JSON.stringify(message).length > 16384) throw new RuntimeError('handshake_too_large');
    const b = message.body, peer = await this.resolvePeer(expected), now = Date.now();
    if (b.profile !== 'oan-session-v1' || b.kind !== kind || !b.sessionId || !b.nonceA || b.initiatorDid === b.responderDid ||
      Object.keys(scope).some(k => b[k as keyof HandshakeScope] !== scope[k as keyof HandshakeScope]) ||
      !Number.isFinite(Date.parse(b.createdAt)) || !Number.isFinite(Date.parse(b.expiresAt)) || Date.parse(b.createdAt) > now + 30000 ||
      Date.parse(b.expiresAt) <= now || Date.parse(b.expiresAt) - Date.parse(b.createdAt) > 60000 || Date.parse(b.expiresAt) <= Date.parse(b.createdAt) || peer.validUntil <= Date.parse(b.expiresAt) || (kind !== 'client-hello' && !b.nonceB)) throw new RuntimeError('handshake_binding_invalid');
    try {
      const v = await compactVerify(message.jws, await importJWK(peer.publicKeyJwk, 'EdDSA'), { algorithms: ['EdDSA'] });
      if (v.protectedHeader.kid !== peer.verificationMethod || v.protectedHeader.typ !== 'oan-session-v1+jws' || !Buffer.from(v.payload).equals(Buffer.from(canonicalJson(b),'utf8'))) throw new Error();
    } catch { throw new RuntimeError('handshake_signature_invalid'); }
  }
  async begin(scope: HandshakeScope): Promise<HandshakeMessage> {
    scope = structuredClone(scope); this.prune();
    if (scope.initiatorDid !== this.localDid || scope.responderDid === this.localDid) throw new RuntimeError('handshake_role_invalid');
    const now = Date.now();
    const hello = await this.signed({ ...scope, profile:'oan-session-v1', kind:'client-hello', sessionId:randomUUID(), nonceA:randomUUID(), nonceB:'', previousDigest:'', createdAt:new Date(now).toISOString(), expiresAt:new Date(now+60000).toISOString() });
    this.states.set(hello.body.sessionId, {role:'initiator',scope,last:hello,stage:'hello'}); return structuredClone(hello);
  }
  async accept(scope: HandshakeScope, input: HandshakeMessage): Promise<HandshakeMessage> {
    scope = structuredClone(scope); const message = structuredClone(input); this.prune();
    if (scope.responderDid !== this.localDid || this.states.has(message.body.sessionId)) throw new RuntimeError('handshake_role_or_replay_invalid');
    await this.check(message,scope,'client-hello',scope.initiatorDid);
    if (message.body.nonceB !== '' || message.body.previousDigest !== '') throw new RuntimeError('handshake_transcript_invalid');
    const reply = await this.signed({...message.body,kind:'server-proof',nonceB:randomUUID(),previousDigest:await digestJson(message)});
    // Re-check after awaits: two concurrent accept calls must not overwrite session state.
    if (this.states.has(message.body.sessionId)) throw new RuntimeError('handshake_replay');
    this.states.set(message.body.sessionId,{role:'responder',scope,last:reply,stage:'server'}); return structuredClone(reply);
  }
  async advance(id: string, input: HandshakeMessage): Promise<{ state:'pending' | 'authenticated'; reply?: HandshakeMessage }> {
    const s = this.states.get(id), message = structuredClone(input);
    if (!s) throw new RuntimeError('session_not_found');
    const old = s.last;
    if (s.stage === 'completed' && s.role === 'responder' && s.acceptedClient === await digestJson(message) && s.confirmation) {
      await this.requireAuthenticated(id,this.localDid,s.scope.initiatorDid);
      return {state:'authenticated',reply:structuredClone(s.confirmation)};
    }
    const kind = s.stage === 'hello' ? 'server-proof' : s.stage === 'server' ? 'client-proof' : s.stage === 'client' ? 'session-confirmed' : undefined;
    if (!kind) throw new RuntimeError('handshake_transition_invalid');
    await this.check(message,s.scope,kind,s.role === 'initiator' ? s.scope.responderDid : s.scope.initiatorDid);
    const b = message.body, p = old.body;
    if (b.sessionId !== id || b.nonceA !== p.nonceA || (s.stage !== 'hello' && b.nonceB !== p.nonceB) || !b.nonceB || b.createdAt !== p.createdAt || b.expiresAt !== p.expiresAt || b.previousDigest !== await digestJson(old)) throw new RuntimeError('handshake_transcript_invalid');
    if (s.last !== old) throw new RuntimeError('handshake_concurrent_transition');
    if (s.stage === 'client') { s.last=message; s.stage='completed'; return {state:'authenticated'}; }
    const reply = await this.signed({...b,kind:s.stage === 'hello' ? 'client-proof' : 'session-confirmed',previousDigest:await digestJson(message)});
    if (s.last !== old) throw new RuntimeError('handshake_concurrent_transition');
    s.last=reply;
    if (s.stage === 'server') { s.stage='completed'; s.acceptedClient=await digestJson(message); s.confirmation=reply; return {state:'authenticated',reply:structuredClone(reply)}; }
    s.stage='client'; return {state:'pending',reply:structuredClone(reply)};
  }
  async requireAuthenticated(id: string, localDid: string, peerDid: string): Promise<SessionRecord> {
    const s = this.states.get(id);
    if (!s || localDid !== this.localDid || s.stage !== 'completed' || peerDid !== (s.role === 'initiator' ? s.scope.responderDid : s.scope.initiatorDid) || Date.parse(s.last.body.expiresAt) <= Date.now()) throw new RuntimeError('session_not_authenticated');
    const peer = await this.resolvePeer(peerDid), own = await this.resolvePeer(localDid);
    if (Math.min(peer.validUntil,own.validUntil) <= Date.now()) throw new RuntimeError('session_evidence_expired');
    return {id,localDid,peerDid,state:'authenticated',expiresAt:s.last.body.expiresAt, binding: { serviceRef:s.scope.serviceRef, protocol:s.scope.protocol, protocolVersion:s.scope.protocolVersion }};
  }
  close(id: string): void { this.states.delete(id); }
}
