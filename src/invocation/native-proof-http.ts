// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { createHash } from 'node:crypto';
import { createVerifiedHttpFetch } from './verified-http.js';
import { splitNativeStreamProof, verifyNativeResponseProof } from '../host/runtime-host.js';
import type { VerifiedPeer } from '../session/handshake.js';
import { RuntimeError } from '../errors.js';
import type { RuntimeHostSessionProof } from '../host/runtime-host.js';
import type { SignedMessage } from '../runtime.js';

export interface NativeProofHttpOptions {
  endpoint: string;
  methods: readonly string[];
  localDid: string;
  peerDid: string;
  /** Trusted route configuration; never inferred from the response. */
  responseProofKind: 'sidecar-response' | 'gateway-response';
  resolvePeer(did: string): Promise<VerifiedPeer>;
  /** Host selects the identity, session, operation and policy. No arbitrary signing. */
  sign(input: { requestId: string; body: Uint8Array; rawBodyDigest: string; method: string; target: string; headers: Headers }): Promise<Record<string, string>>;
  onVerified?(receipt: { requestId: string; requestDigest: string; responseDigest: string; status: number; signature: 'verified' }): void;
  maxResponseBytes?: number;
  timeoutMs?: number;
  transport?: typeof fetch;
}

/** Native HTTP proof profile. No registration, discovery, task planning or process
 * management. Each call owns its correlation state, including failed dispatches.
 * SSE is buffered and authenticated before delivery, not trusted live streaming.
 */
export function createNativeProofHttpFetch(options: NativeProofHttpOptions): typeof fetch {
  const config = { ...options, methods: [...options.methods] };
  if (typeof config.localDid !== 'string' || !config.localDid.trim()
    || typeof config.peerDid !== 'string' || !config.peerDid.trim()
    || typeof config.sign !== 'function' || typeof config.resolvePeer !== 'function'
    || !['sidecar-response', 'gateway-response'].includes(config.responseProofKind)) throw new RuntimeError('invalid_native_proof_config');
  // Validate endpoint and limits at construction, without making a request.
  createVerifiedHttpFetch({ ...config, sign: async () => ({}), verify: async () => {} });
  return async (input, init) => {
    let requestDigest: string | undefined;
    const protectedFetch = createVerifiedHttpFetch({ ...config,
      sign: async request => {
        requestDigest = `sha256:${createHash('sha256').update(request.body).digest('hex')}`;
        return config.sign({ ...request, rawBodyDigest: requestDigest });
      },
      verify: async ({ requestId, body, headers, status }) => {
        const terminal = headers.get('content-type')?.toLowerCase().startsWith('text/event-stream')
          ? splitNativeStreamProof(body)
          : { body, encodedProof: headers.get('x-oan-response-envelope') };
        if (!requestDigest || !terminal.encodedProof) throw new RuntimeError('response_proof_missing');
        const signed = await verifyNativeResponseProof({ encodedProof: terminal.encodedProof,
          responseBody: terminal.body, status,
          expected: { kind: config.responseProofKind, senderDid: config.peerDid, audienceDid: config.localDid,
            targetResourceDid: config.peerDid, requestId: requestId, requestPayloadDigest: requestDigest },
          resolvePeer: config.resolvePeer });
        config.onVerified?.({ requestId, requestDigest, responseDigest: signed.payloadDigest as string,
          status, signature: 'verified' });
      },
    });
    return protectedFetch(input, init);
  };
}

/** Optional registered-actor composition. Hosts still establish the session and
 * explicitly choose operation policy and response profile. No peer discovery,
 * business planning, implicit authorization or deployment management occurs. */
export function createActorNativeHttpFetch(options: Omit<NativeProofHttpOptions, 'localDid' | 'peerDid' | 'resolvePeer' | 'sign'> & {
  actor: {
    did: string; tenantId?: string;
    resolvePeer(did: string): Promise<VerifiedPeer>;
    signRequest(proof: RuntimeHostSessionProof, requestId: string, rawBodyDigest: string, operation: string,
      httpBinding: { method: string; target: string; mcpSessionId: string }): Promise<SignedMessage>;
  };
  session: RuntimeHostSessionProof;
  /** Trusted adapter maps actual native requests to host-authorized operations. */
  operation: string | ((request: { method: string; target: string; body: Uint8Array; headers: Headers }) => string);
}): typeof fetch {
  const { actor, operation, ...rest } = options;
  const session = structuredClone(options.session);
  if (session.scope.initiatorDid !== actor.did || !session.scope.responderDid
    || (typeof operation !== 'function' && (typeof operation !== 'string' || !operation.trim()))) throw new RuntimeError('invalid_native_proof_config');
  const did = actor.did, tenantId = actor.tenantId;
  const signRequest = actor.signRequest.bind(actor), resolvePeer = actor.resolvePeer.bind(actor);
  return createNativeProofHttpFetch({ ...rest, localDid: did, peerDid: session.scope.responderDid, resolvePeer,
    sign: async request => {
      const selected = typeof operation === 'function' ? operation({ ...request, body: new Uint8Array(request.body), headers: new Headers(request.headers) }) : operation;
      if (typeof selected !== 'string' || !selected.trim()) throw new RuntimeError('invalid_native_operation');
      const message = await signRequest(session, request.requestId, request.rawBodyDigest, selected,
        { method: request.method, target: request.target, mcpSessionId: request.headers.get('mcp-session-id') ?? '' });
      return { 'x-oan-request-id': request.requestId, 'x-oan-envelope': Buffer.from(JSON.stringify({
        targetResourceDid: session.scope.responderDid, sessionId: session.transcript[0].body.sessionId,
        ...(tenantId !== undefined ? { tenantId } : {}), message })).toString('base64url') };
    } });
}

