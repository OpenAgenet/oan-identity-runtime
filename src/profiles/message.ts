// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { SignIntent } from '../policy/index.js';
import { RuntimeError } from '../errors.js';
export function validateMessageBinding(input: Pick<SignIntent, 'purpose' | 'serviceRef' | 'protocolVersion' | 'requestDigest' | 'stream'>): void {
  const hash = /^sha256:[a-f0-9]{64}$/;
  if (!input.serviceRef || !input.protocolVersion || (input.purpose === 'response' && !hash.test(input.requestDigest ?? ''))) throw new RuntimeError('message_correlation_required');
  if (input.purpose === 'event' && (!hash.test(input.requestDigest ?? '') || !input.stream || !Number.isSafeInteger(input.stream.sequence) || input.stream.sequence < 0 || !input.stream.taskId || !hash.test(input.stream.previousDigest) || !['partial', 'complete', 'cancelled'].includes(input.stream.state) || (input.stream.artifactDigest !== undefined && !hash.test(input.stream.artifactDigest)) || (input.stream.callbackDid !== undefined && !input.stream.callbackDid) || (input.stream.nonce !== undefined && (!input.stream.nonce || input.stream.nonce.length > 256)))) throw new RuntimeError('stream_correlation_required');
}
