// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { RuntimeError } from '../errors.js';
import { DatabaseSync } from 'node:sqlite';
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

/** Durable atomic replay protection for a single host or a small multi-process deployment. */
export class SqliteReplayStore implements ReplayStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS oan_replay (scope TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(scope, nonce))');
  }
  async consume(scope: string, nonce: string, expiresAt: number, now = Date.now()): Promise<void> {
    if (!nonce || !Number.isFinite(expiresAt) || expiresAt <= now) throw new RuntimeError('nonce_expired_or_invalid');
    this.db.prepare('DELETE FROM oan_replay WHERE expires_at <= ?').run(now);
    try { this.db.prepare('INSERT INTO oan_replay(scope,nonce,expires_at) VALUES (?,?,?)').run(scope, nonce, expiresAt); }
    catch { throw new RuntimeError('replay_detected'); }
  }
  close(): void { this.db.close(); }
}
export interface SessionRecord { id: string; localDid: string; peerDid: string; expiresAt: string; state: 'challenged' | 'authenticated' | 'closed'; binding?: { serviceRef: string; protocol: string; protocolVersion: string } }
/** The evidence verifier, not an adapter, must approve authentication transitions. */
export interface SessionManager {
  requireAuthenticated(id: string, localDid: string, peerDid: string): Promise<SessionRecord>;
  /** Durable multi-caller hosts additionally bind sessions to the authenticated owner. */
  requireAuthenticatedForCaller?(caller:import('../policy/index.js').CallerContext,id:string,localDid:string,peerDid:string):Promise<SessionRecord>;
}

/** Separate from business signing to avoid requiring authentication before the handshake. */
export interface SessionHandshake {
  begin(caller: import('../policy/index.js').CallerContext, input: { localIdentityRef: string; peerDid: string; serviceRef: string; protocol: 'http' | 'mcp' | 'a2a'; protocolVersion: string }): Promise<{ handshakeId: string; clientHello: unknown }>;
  /** Inbound first contact; peerMessage never supplies trusted session state. */
  accept(caller: import('../policy/index.js').CallerContext, input: { localIdentityRef: string; expectedPeerDid: string; serviceRef: string; protocol: 'http' | 'mcp' | 'a2a'; protocolVersion: string }, peerMessage: unknown): Promise<{ handshakeId: string; serverHello: unknown }>;
  advance(caller: import('../policy/index.js').CallerContext, handshakeId: string, peerMessage: unknown): Promise<{ state: 'pending' | 'authenticated'; reply?: unknown; session?: SessionRecord }>;
  close(caller: import('../policy/index.js').CallerContext, sessionId: string): Promise<void>;
}

/** Independent identity verification may travel through agent messages or files.
 * It does not require a network business service or an authenticated business session.
 * Host authenticates caller/tenant; peer JSON never supplies trusted state.
 */
export interface IdentityVerificationScope {
  identityRef: string;
  peerDid: string;
  purpose: string;
  scope: string;
  profile: 'oan-session-v1';
  serviceRef: string;
  protocol: 'http' | 'mcp' | 'a2a';
  protocolVersion: string;
}
export type IdentityEvidenceState = 'valid' | 'invalid' | 'unknown' | 'not_applicable';
export interface IdentityVerificationStatus {
  sessionRef: string;
  localDid: string;
  peerDid: string;
  purpose: string;
  scope: string;
  expiresAt: string;
  state: 'pending' | 'completed' | 'rejected' | 'expired' | 'closed';
  evidence: Array<{ name: string; status: IdentityEvidenceState; source?: string; observedAt?: string }>;
  peerPossession: 'not_checked' | 'valid' | 'invalid';
  peerConfirmation: 'pending' | 'verified';
  /** A completed handshake does not protect subsequent business traffic. */
  businessProtection: 'not_established';
  /** Last locally signed public message for safe recovery; never trusted journal state. */
  outgoing?: PublicIdentityHandshakeMessage;
}
/** Bounded, schema-validated public messages only. No identity bundles or local refs. */
export interface PublicIdentityHandshakeMessage {
  profile: 'oan-session-v1';
  kind: 'client-hello' | 'server-proof' | 'client-proof' | 'session-confirmed';
  /** Concrete wire schema/signature/transcript validation remains an implementation gate. */
  body: unknown;
  jws: string;
}
/** Common core for Skill, CLI and MCP, implemented by DurableIdentityVerification.
 * Caller is authenticated by the local Host; transport only exchanges public messages.
 * finish requires signed SessionConfirmed, never a natural-language acknowledgement.
 */
export interface IdentityVerificationWorkflow {
  begin(caller: import('../policy/index.js').CallerContext, input: IdentityVerificationScope): Promise<{ sessionRef: string; outgoing: PublicIdentityHandshakeMessage }>;
  accept(caller: import('../policy/index.js').CallerContext, input: IdentityVerificationScope, message: PublicIdentityHandshakeMessage): Promise<{ sessionRef: string; outgoing: PublicIdentityHandshakeMessage }>;
  advance(caller: import('../policy/index.js').CallerContext, sessionRef: string, message: PublicIdentityHandshakeMessage): Promise<{ status: IdentityVerificationStatus; outgoing?: PublicIdentityHandshakeMessage }>;
  inspect(caller: import('../policy/index.js').CallerContext, sessionRef: string): Promise<IdentityVerificationStatus>;
  close(caller: import('../policy/index.js').CallerContext, sessionRef: string): Promise<void>;
}
