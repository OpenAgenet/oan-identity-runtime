// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { CallerContext, SignIntent } from '../policy/index.js';
import type { IdentityRuntime, SignedMessage } from '../runtime.js';
import type { SessionManager, ReplayStore } from '../session/index.js';
import type { VerifiedPeer } from '../session/handshake.js';
import type { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import { RuntimeError } from '../errors.js';
import { digestJson, verifyPinnedMessage } from '../verification/index.js';
import { DurableStreamVerifier, type StreamEventInput } from './stream.js';

export interface StreamingProfile {
  protocol: 'a2a'; protocolVersion: string; serviceRef: string; operation: string;
}
export interface StreamingInvocationOptions {
  identityRef: string; localDid: string; peerDid: string; runtime: IdentityRuntime;
  sessions: SessionManager; replay: ReplayStore; resolvePeer: (did: string) => Promise<VerifiedPeer>;
  profile: StreamingProfile; journal: EncryptedKeyProvider; streams: DurableStreamVerifier;
  authorize: (caller: CallerContext, payload: unknown, purpose: 'event') => Promise<void>;
}

/** A2A event boundary. Signature/evidence checks precede the durable sequence gate. */
export class StreamingInvocation {
  constructor(private readonly options: StreamingInvocationOptions) {
    if (!options.profile.serviceRef || !options.profile.operation || !options.profile.protocolVersion) throw new RuntimeError('invalid_protocol_profile');
  }
  private eventIntent(sessionId: string, requestId: string, payload: unknown, event: StreamEventInput): SignIntent {
    return { identityRef: this.options.identityRef, audienceDid: this.options.peerDid, purpose: 'event', protocol: 'a2a', protocolVersion: this.options.profile.protocolVersion,
      operation: this.options.profile.operation, serviceRef: this.options.profile.serviceRef, requestDigest: event.requestDigest, sessionId, requestId,
      stream: { taskId: event.taskId, sequence: event.sequence, previousDigest: event.previousDigest, state: event.state, artifactDigest: event.artifactDigest, callbackDid: event.callbackDid }, payload };
  }
  async prepareEvent(caller: CallerContext, sessionId: string, event: StreamEventInput, payload: unknown): Promise<{ message: SignedMessage; event: StreamEventInput }> {
    const input = structuredClone(event), object = structuredClone(payload), bound = structuredClone(caller);
    await this.options.authorize(bound, object, 'event');
    const message = await this.options.runtime.signIntent(bound, this.eventIntent(sessionId, input.requestId, object, input));
    const messageDigest = await digestJson({ context: message.context, operation: message.operation, serviceRef: message.serviceRef,
      protocolVersion: message.protocolVersion, ...(message.requestDigest ? { requestDigest: message.requestDigest } : {}),
      ...(message.stream ? { stream: message.stream } : {}), payload: message.payload });
    return { message, event: { ...input, nonce: message.context.nonce, messageDigest } };
  }
  async receiveEvent(caller: CallerContext, message: SignedMessage, event: StreamEventInput, payload: unknown): Promise<{ accepted: true; terminal: boolean }> {
    const bound = structuredClone(caller), snapshot = structuredClone(message), input = structuredClone(event), object = structuredClone(payload);
    if (snapshot.context.purpose !== 'event' || snapshot.context.protocol !== 'a2a') throw new RuntimeError('stream_profile_mismatch');
    if (input.sessionId !== snapshot.context.sessionId || input.peerDid !== snapshot.context.senderDid
      || input.audienceDid !== snapshot.context.audienceDid || input.requestDigest !== snapshot.requestDigest || input.nonce !== snapshot.context.nonce
      || input.requestId !== snapshot.context.requestId) throw new RuntimeError('stream_binding_mismatch');
    await this.options.sessions.requireAuthenticatedForCaller?.(bound, snapshot.context.sessionId, this.options.localDid, this.options.peerDid);
    const peer = await this.options.resolvePeer(this.options.peerDid);
    await verifyPinnedMessage(snapshot, { senderDid: this.options.peerDid, audienceDid: this.options.localDid,
      verificationMethod: peer.verificationMethod, publicKeyJwk: peer.publicKeyJwk, serviceRef: this.options.profile.serviceRef,
      protocolVersion: this.options.profile.protocolVersion, operation: this.options.profile.operation, requestDigest: input.requestDigest,
      sessionId: snapshot.context.sessionId, requestId: input.requestId, purpose: 'event', protocol: 'a2a', replay: this.options.replay, consumeReplay: false });
    if (snapshot.context.requestId !== input.requestId || snapshot.context.payloadDigest !== await digestJson(object)
      || !snapshot.stream || snapshot.stream.taskId !== input.taskId || snapshot.stream.sequence !== input.sequence
      || snapshot.stream.previousDigest !== input.previousDigest || snapshot.stream.state !== input.state
      || snapshot.stream.artifactDigest !== input.artifactDigest || snapshot.stream.callbackDid !== input.callbackDid) throw new RuntimeError('stream_binding_mismatch');
    const messageDigest = await digestJson({ context: snapshot.context, operation: snapshot.operation, serviceRef: snapshot.serviceRef,
      protocolVersion: snapshot.protocolVersion, ...(snapshot.requestDigest ? { requestDigest: snapshot.requestDigest } : {}),
      ...(snapshot.stream ? { stream: snapshot.stream } : {}), payload: snapshot.payload });
    if (input.messageDigest !== messageDigest) throw new RuntimeError('stream_message_digest_mismatch');
    const result = await this.options.streams.accept(bound, input);
    return { accepted: true, terminal: result.terminal };
  }
}
