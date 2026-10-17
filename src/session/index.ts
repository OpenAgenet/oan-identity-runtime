// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { RuntimeError } from '../errors.js';
/** Process-local bounded replay cache. Restart persistence is a later milestone. */
/** Must consume atomically. Durable/multi-process adapters implement this port. */
export interface ReplayStore { consume(scope: string, nonce: string, expiresAt: number, now?: number): Promise<void> }
export class ReplayCache implements ReplayStore {
  private readonly entries = new Map<string, number>();
  constructor(private readonly maxEntries = 10000) {}
  async consume(scope: string, nonce: string, expiresAt: number, now = Date.now()): Promise<void> {
    if (!nonce || !Number.isFinite(expiresAt) || expiresAt <= now) throw new RuntimeError('nonce_expired_or_invalid');
    for (const [key, expiry] of this.entries) if (expiry <= now) this.entries.delete(key);
    const key = JSON.stringify([scope, nonce]);
    if (this.entries.has(key)) throw new RuntimeError('replay_detected');
    if (this.entries.size >= this.maxEntries) throw new RuntimeError('replay_cache_full');
    this.entries.set(key, expiresAt);
  }
}
export interface SessionRecord { id: string; localDid: string; peerDid: string; expiresAt: string; state: 'challenged' | 'authenticated' | 'closed' }
/** The evidence verifier, not an adapter, must approve authentication transitions. */
export interface SessionManager { requireAuthenticated(id: string, localDid: string, peerDid: string): Promise<SessionRecord> }

/** Separate from business signing to avoid requiring authentication before the handshake. */
export interface SessionHandshake {
  begin(caller: import('../policy/index.js').CallerContext, input: { localIdentityRef: string; peerDid: string; serviceRef: string; protocol: 'http' | 'mcp' | 'a2a'; protocolVersion: string }): Promise<{ handshakeId: string; clientHello: unknown }>;
  /** Inbound first contact; peerMessage never supplies trusted session state. */
  accept(caller: import('../policy/index.js').CallerContext, input: { localIdentityRef: string; expectedPeerDid: string; serviceRef: string; protocol: 'http' | 'mcp' | 'a2a'; protocolVersion: string }, peerMessage: unknown): Promise<{ handshakeId: string; serverHello: unknown }>;
  advance(caller: import('../policy/index.js').CallerContext, handshakeId: string, peerMessage: unknown): Promise<{ state: 'pending' | 'authenticated'; reply?: unknown; session?: SessionRecord }>;
  close(caller: import('../policy/index.js').CallerContext, sessionId: string): Promise<void>;
}
