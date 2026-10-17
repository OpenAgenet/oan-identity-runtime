// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { CallerContext } from '../policy/index.js';
import type { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import { RuntimeError } from '../errors.js';
import { digestJson } from '../verification/index.js';

export const STREAM_GENESIS_DIGEST = `sha256:${'0'.repeat(64)}`;
const HASH = /^sha256:[a-f0-9]{64}$/;

export type StreamEventStatus = 'partial' | 'complete' | 'cancelled';
export interface StreamEventInput {
  streamId: string;
  taskId: string;
  sessionId: string;
  requestId: string;
  peerDid: string;
  audienceDid: string;
  requestDigest: string;
  nonce: string;
  sequence: number;
  previousDigest: string;
  messageDigest: string;
  state: StreamEventStatus;
  /** Optional artifact/callback binding. The digest is checked against the supplied value. */
  artifact?: unknown;
  artifactDigest?: string;
  callbackDid?: string;
}
interface StreamRecord {
  owner: CallerContext;
  stream: Omit<StreamEventInput, 'artifact' | 'artifactDigest'> & { artifactDigest?: string };
  nonce: string;
  seenNonces: string[];
  lastDigest: string;
  terminal: boolean;
}

/**
 * Durable event ordering gate. Signature verification happens before this gate;
 * this class prevents a validly signed event from being accepted out of order,
 * twice, for the wrong task/audience, or after a terminal event.
 */
export class DurableStreamVerifier {
  constructor(private readonly store: EncryptedKeyProvider, private readonly authorize?: (caller: CallerContext, event: StreamEventInput) => Promise<void>) {}
  private key(id: string) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) throw new RuntimeError('invalid_stream_id');
    return `stream:v1:${id}`;
  }
  async accept(caller: CallerContext, event: StreamEventInput): Promise<{ sequence: number; state: StreamEventStatus; terminal: boolean }> {
    const input = structuredClone(event);
    if (!caller.callerId || !input.taskId || !input.sessionId || !input.requestId || !input.peerDid || !input.audienceDid
      || !input.nonce || input.nonce.length > 256 || !HASH.test(input.requestDigest) || !HASH.test(input.previousDigest) || !HASH.test(input.messageDigest)
      || !Number.isSafeInteger(input.sequence) || input.sequence < 0 || !['partial', 'complete', 'cancelled'].includes(input.state)
      || (input.callbackDid !== undefined && input.callbackDid !== input.peerDid)
      || (input.artifact !== undefined && (!input.artifactDigest || !HASH.test(input.artifactDigest)))) throw new RuntimeError('invalid_stream_event');
    if (input.artifact !== undefined && input.artifactDigest !== await digestJson(input.artifact)) throw new RuntimeError('artifact_digest_mismatch');
    await this.authorize?.(structuredClone(caller), structuredClone(input));
    const id = this.key(input.streamId), row = await this.store.readRecord<StreamRecord>(id);
    if (!row) {
      if (input.sequence !== 0 || input.previousDigest !== STREAM_GENESIS_DIGEST) throw new RuntimeError('stream_sequence_gap');
      const { artifact: _artifact, ...publicInput } = input;
      const record: StreamRecord = { owner: structuredClone(caller), stream: { ...publicInput, artifactDigest: input.artifactDigest }, nonce: input.nonce, seenNonces: [input.nonce], lastDigest: input.messageDigest, terminal: input.state !== 'partial' };
      await this.store.commitRecords([{ id, expectedGeneration: 0, value: record }]);
      return { sequence: input.sequence, state: input.state, terminal: record.terminal };
    }
    if (row.value.owner.callerId !== caller.callerId || row.value.owner.tenantId !== caller.tenantId) throw new RuntimeError('stream_access_denied');
    const previous = row.value.stream;
    if (row.value.terminal) throw new RuntimeError('stream_terminal');
    if (row.value.seenNonces.includes(input.nonce)) throw new RuntimeError('stream_duplicate_or_reordered');
    if (input.taskId !== previous.taskId || input.sessionId !== previous.sessionId || input.requestId !== previous.requestId
      || input.peerDid !== previous.peerDid || input.audienceDid !== previous.audienceDid || input.requestDigest !== previous.requestDigest) throw new RuntimeError('stream_binding_mismatch');
    if (input.sequence !== previous.sequence + 1) throw new RuntimeError(input.sequence <= previous.sequence ? 'stream_duplicate_or_reordered' : 'stream_sequence_gap');
    if (input.previousDigest !== row.value.lastDigest) throw new RuntimeError('stream_previous_digest_mismatch');
    const terminal = input.state !== 'partial';
    const { artifact: _artifact, ...publicInput } = input;
    if (row.value.seenNonces.length >= 4096) throw new RuntimeError('stream_replay_history_full');
    const next: StreamRecord = { owner: structuredClone(caller), stream: { ...publicInput, artifactDigest: input.artifactDigest }, nonce: input.nonce, seenNonces: [...row.value.seenNonces, input.nonce], lastDigest: input.messageDigest, terminal };
    await this.store.commitRecords([{ id, expectedGeneration: row.generation, value: next }]);
    return { sequence: input.sequence, state: input.state, terminal };
  }
  async inspect(caller: CallerContext, streamId: string): Promise<StreamEventStatus | 'not_found'> {
    const row = await this.store.readRecord<StreamRecord>(this.key(streamId));
    if (!row) return 'not_found';
    if (row.value.owner.callerId !== caller.callerId || row.value.owner.tenantId !== caller.tenantId) throw new RuntimeError('stream_access_denied');
    return row.value.stream.state;
  }
}
