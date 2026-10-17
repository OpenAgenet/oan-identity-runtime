// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import type { SignedMessage } from '../runtime.js';
import type { SessionManager, ReplayStore } from '../session/index.js';
import type { VerifiedPeer } from '../session/handshake.js';
import { digestJson, verifyPinnedMessage } from '../verification/index.js';
import { RuntimeError } from '../errors.js';

/** Trusted adapter pins the actual operation/payload and the expected peer, never peer JSON. */
export async function verifyProtectedInvocation(message: SignedMessage, input: {
  localDid: string; peerDid: string; sessionId: string; requestId: string;
  purpose: 'request' | 'response'; protocol: 'mcp' | 'http' | 'a2a'; protocolVersion: string;
  operation: string; serviceRef: string; payload: unknown; requestDigest?: string;
  sessions: SessionManager; replay: ReplayStore; resolvePeer: (did: string) => Promise<VerifiedPeer>;
  authorize: () => Promise<void>;
}) {
  const snapshot = structuredClone(message), payload = structuredClone(input.payload);
  await input.authorize();
  const session = await input.sessions.requireAuthenticated(input.sessionId, input.localDid, input.peerDid);
  if (session.binding && (session.binding.serviceRef !== input.serviceRef || session.binding.protocol !== input.protocol || session.binding.protocolVersion !== input.protocolVersion)) throw new RuntimeError('session_scope_mismatch');
  const peer = await input.resolvePeer(input.peerDid);
  if (peer.did !== input.peerDid || peer.validUntil <= Date.now() || await digestJson(snapshot.payload) !== await digestJson(payload)) throw new RuntimeError('invocation_binding_or_evidence_invalid');
  await verifyPinnedMessage(snapshot, { senderDid: input.peerDid, audienceDid: input.localDid,
    verificationMethod:peer.verificationMethod,publicKeyJwk:peer.publicKeyJwk,
    serviceRef:input.serviceRef,protocolVersion:input.protocolVersion,operation:input.operation,
    requestDigest:input.requestDigest,sessionId:input.sessionId,requestId:input.requestId,
    purpose:input.purpose,protocol:input.protocol,replay:input.replay });
  return { signatureValid:true, registrationTrust:'verified_pinned_root', requestDigest:await digestJson(snapshot), payloadDigest:await digestJson(payload) };
}
