// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { DatabaseSync } from 'node:sqlite';
import { RuntimeError } from '../errors.js';
import type { EncryptedBlobStore, StoredBlob, BlobMutation } from './index.js';
/** One local SQLite database; encryption keys must come from a separate provider. */
export class SqliteBlobStore implements EncryptedBlobStore {
  private readonly db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, generation INTEGER NOT NULL, ciphertext TEXT NOT NULL)');
  }
  async load(id: string): Promise<StoredBlob | undefined> {
    const row = this.db.prepare('SELECT generation, ciphertext FROM blobs WHERE id=?').get(id);
    return row ? { generation: Number(row.generation), ciphertext: String(row.ciphertext) } : undefined;
  }
  async compareAndSwap(id: string, expected: number, ciphertext: string): Promise<number> {
    return this.apply(id, expected, ciphertext);
  }
  private apply(id: string, expected: number, ciphertext: string): number {
    if (!Number.isSafeInteger(expected) || expected < 0 || expected >= Number.MAX_SAFE_INTEGER) throw new RuntimeError('invalid_generation');
    const result = expected === 0
      ? this.db.prepare('INSERT OR IGNORE INTO blobs VALUES (?,1,?)').run(id, ciphertext)
      : this.db.prepare('UPDATE blobs SET generation=generation+1,ciphertext=? WHERE id=? AND generation=?').run(ciphertext, id, expected);
    if (Number(result.changes) !== 1) throw new RuntimeError('store_generation_conflict');
    return expected + 1;
  }
  async commit(mutations: readonly BlobMutation[]): Promise<void> {
    if (new Set(mutations.map(m => m.id)).size !== mutations.length) throw new RuntimeError('duplicate_store_mutation');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      // Do not await inside the transaction: the synchronous SQLite driver cannot interleave writes.
      for (const mutation of mutations) this.apply(mutation.id, mutation.expectedGeneration, mutation.ciphertext);
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  close(): void { this.db.close(); }
}
