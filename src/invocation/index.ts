// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { CallerContext, SignIntent } from '../policy/index.js';
import type { PreparedInvocation } from '../profiles/index.js';
import type { SignedMessage } from '../runtime.js';

/** A future trusted implementation composes evidence, session and message verification.
 * These are contracts only: a caller-constructed report never authorizes execution.
 */
export interface InboundAuthorization {
  authorize(caller: CallerContext, input: {
    message: SignedMessage;
    expected: PreparedInvocation & { localDid: string; peerDid: string; sessionId: string; requestId: string };
  }): Promise<void>;
}
/** Enforcement point calls handler only AFTER verification and object-level policy.
 * Outbound implementations verify the result BEFORE exposing it as trusted content.
 * No implementation or public entry point is enabled by these contracts.
 */
export interface ProtectedInvocation {
  execute(caller: CallerContext, input: {
    identityRef: string; peerDid: string; invocation: PreparedInvocation;
  }): Promise<{ result: unknown; request: SignedMessage; response: SignedMessage }>;
}
/** Stream correlation requires durable/atomic ordering, not only signed sequence fields. */
export interface StreamVerifier {
  accept(input: {
    peerDid: string; audienceDid: string; sessionId: string; serviceRef: string;
    requestId: string; requestDigest: string; messageDigest: string;
    stream: NonNullable<SignIntent['stream']>;
  }): Promise<void>;
}

export { DurableStreamVerifier, STREAM_GENESIS_DIGEST, type StreamEventInput, type StreamEventStatus } from './stream.js';
