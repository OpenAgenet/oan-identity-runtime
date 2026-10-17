// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { randomUUID } from 'node:crypto';
import type { AuditEvent, AuditSink } from './index.js';
import type { EncryptedKeyProvider } from '../key-provider/encrypted.js';
/** Append-only encrypted host records. Allowlist fields to exclude accidental payload/key logging. */
export class EncryptedAuditSink implements AuditSink {
  constructor(private readonly keys:EncryptedKeyProvider){}
  async append(event:AuditEvent):Promise<void>{
    const {timestamp,action,outcome,identityRef,code}=event;
    await this.keys.commitRecords([{id:'host:audit:'+randomUUID(),expectedGeneration:0,
      value:{timestamp,action,outcome,identityRef,...(code?{code}:{})}}]);
  }
}
