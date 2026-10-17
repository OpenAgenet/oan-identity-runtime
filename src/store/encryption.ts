// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { RuntimeError } from '../errors.js';
/** Bind ciphertext to both record ID and generation. Never store the key beside it. */
export function sealBlob(plaintext: string, key: Uint8Array, id: string, generation: number): string {
  if (key.byteLength !== 32) throw new RuntimeError('invalid_encryption_key');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(JSON.stringify([id, generation]), 'utf8'));
  const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return JSON.stringify({ version: 1, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), data: data.toString('base64url') });
}
export function openBlob(blob: string, key: Uint8Array, id: string, generation: number): string {
  try {
    const value = JSON.parse(blob);
    if (value.version !== 1 || key.byteLength !== 32) throw new Error();
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.iv, 'base64url'));
    decipher.setAAD(Buffer.from(JSON.stringify([id, generation]), 'utf8'));
    decipher.setAuthTag(Buffer.from(value.tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(value.data, 'base64url')), decipher.final()]).toString('utf8');
  } catch { throw new RuntimeError('encrypted_blob_authentication_failed'); }
}
