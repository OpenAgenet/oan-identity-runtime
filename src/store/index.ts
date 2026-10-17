// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

export interface BlobMutation { id: string; expectedGeneration: number; ciphertext: string }
export interface StoredBlob { generation: number; ciphertext: string }
/** Store encrypted blobs only; CAS prevents silent concurrent replacement. */
export interface EncryptedBlobStore {
  load(id: string): Promise<StoredBlob | undefined>;
  compareAndSwap(id: string, expectedGeneration: number, ciphertext: string): Promise<number>;
  /** Atomically update journal, catalog and encrypted records in one transaction. */
  commit(mutations: readonly BlobMutation[]): Promise<void>;
  close(): void;
}
