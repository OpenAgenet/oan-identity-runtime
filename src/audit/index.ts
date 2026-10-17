// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

export interface AuditEvent { timestamp: string; action: string; outcome: 'allowed' | 'denied'; code?: string; identityRef: string }
/** No payloads, keys, credentials, tokens or arbitrary error objects. */
export interface AuditSink { append(event: AuditEvent): Promise<void> }
export class MemoryAuditSink implements AuditSink {
  private readonly records: AuditEvent[] = [];
  async append(event: AuditEvent): Promise<void> { this.records.push({ ...event }); }
  list(): AuditEvent[] { return this.records.map(e => ({ ...e })); }
}
