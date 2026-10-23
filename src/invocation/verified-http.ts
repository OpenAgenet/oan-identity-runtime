// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { randomUUID } from 'node:crypto';
import { RuntimeError } from '../errors.js';
import { splitNativeStreamProof } from '../host/runtime-host.js';

/** Trusted host callbacks can use embedded Runtime or authenticated IPC.
 * Protocol clients provide only their ordinary fetch hook; no keys enter the SDK.
 */
export function createVerifiedHttpFetch(options: {
  endpoint: string;
  methods: readonly string[];
  maxResponseBytes?: number;
  timeoutMs?: number;
  sign(input: { requestId: string; body: Uint8Array; method: string; target: string; headers: Headers }): Promise<Record<string, string>>;
  verify(input: { requestId: string; body: Uint8Array; headers: Headers; status: number }): Promise<void>;
  transport?: typeof fetch;
}): typeof fetch {
  const endpoint = new URL(options.endpoint).href;
  const limit = options.maxResponseBytes ?? 1024 * 1024;
  const timeout = options.timeoutMs ?? 30000;
  const methods = [...options.methods], sign = options.sign, verify = options.verify, transport = options.transport ?? fetch;
  if (!Number.isSafeInteger(limit) || limit <= 0) throw new RuntimeError('invalid_response_limit');
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw new RuntimeError('invalid_http_timeout');
  return async (input, init) => {
    const destination = input instanceof Request ? input.url : String(input);
    // Request objects require body/header merging; deliberately fail closed until
    // an explicit profile supports them. Pinned native SDKs use URL + RequestInit.
    if (input instanceof Request || new URL(destination).href !== endpoint || !init
      || !methods.includes(init.method ?? 'GET') || (init.body != null && typeof init.body !== 'string')) throw new RuntimeError('unsupported_protected_http_request');
    const snapshot = { ...init, headers: new Headers(init.headers) };
    const signal = AbortSignal.any([AbortSignal.timeout(timeout), ...(snapshot.signal ? [snapshot.signal] : [])]);
    signal.throwIfAborted();
    const requestId = randomUUID();
    const body = new TextEncoder().encode(typeof snapshot.body === 'string' ? snapshot.body : '');
    const headers = snapshot.headers;
    const target = new URL(endpoint);
    for (const [name, value] of Object.entries(await sign({ requestId, body: new Uint8Array(body), method: snapshot.method ?? 'GET', target: target.pathname + target.search, headers: new Headers(headers) }))) headers.set(name, value);
    signal.throwIfAborted();
    const response = await transport(endpoint, { ...snapshot, headers, signal, redirect: 'error' });
    const chunks: Uint8Array[] = []; let size = 0;
    const reader = response.body?.getReader();
    try {
      if (reader) for (;;) {
        const next = await reader.read(); if (next.done) break;
        size += next.value.length;
        if (size > limit) throw new RuntimeError('protected_response_too_large');
        chunks.push(next.value);
      }
    } catch (error) { await reader?.cancel().catch(() => {}); throw error; }
    finally { reader?.releaseLock(); }
    const bytes = Buffer.concat(chunks);
    signal.throwIfAborted();
    await verify({ requestId, body: bytes, headers: new Headers(response.headers), status: response.status });
    signal.throwIfAborted();
    const native = response.headers.get('content-type')?.startsWith('text/event-stream') ? splitNativeStreamProof(bytes).body : bytes;
    const cleanHeaders = new Headers(response.headers);
    for (const name of ['content-length', 'transfer-encoding', 'content-encoding', 'x-oan-response-envelope']) cleanHeaders.delete(name);
    return new Response([204, 205, 304].includes(response.status) ? null : new Uint8Array(native), { status: response.status, statusText: response.statusText, headers: cleanHeaders });
  };
}
