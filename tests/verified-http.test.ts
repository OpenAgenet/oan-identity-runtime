// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { createVerifiedHttpFetch } from '../src/invocation/verified-http.js';

test('protected fetch authenticates before exposing data and removes terminal proof from native SSE', async () => {
  const body = 'event: message\ndata: {"id":1}\n\n';
  let verified = false;
  const call = createVerifiedHttpFetch({ endpoint: 'http://127.0.0.1:1234/mcp', methods: ['POST'],
    sign: async input => { assert.equal(input.method, 'POST'); assert.equal(input.target, '/mcp'); assert.equal(input.headers.get('mcp-session-id'), 'native-session'); return { 'x-oan-envelope': 'signed' }; },
    verify: async input => { assert.match(Buffer.from(input.body).toString(), /oan-response-proof/); verified = true; },
    transport: async (_url, init) => { assert.equal(init?.redirect, 'error'); assert.equal(new Headers(init?.headers).get('x-oan-envelope'), 'signed'); return new Response(body + '\nevent: oan-response-proof\ndata: YWJj\n\n', { headers: { 'content-type': 'text/event-stream', 'content-length': '999', 'mcp-session-id': 'session' } }); } });
  const response = await call('http://127.0.0.1:1234/mcp', { method: 'POST', body: '{}', headers: { 'mcp-session-id': 'native-session' } });
  assert.equal(verified, true); assert.equal(await response.text(), body);
  assert.equal(response.headers.get('mcp-session-id'), 'session'); assert.equal(response.headers.get('content-length'), null);
});

test('protected fetch denies destination changes, redirects, oversized and unverified responses', async () => {
  let signs = 0, verifies = 0;
  const options = { endpoint: 'http://127.0.0.1:1234/mcp', methods: ['POST'], maxResponseBytes: 3,
    sign: async () => { signs++; return {}; }, verify: async () => { verifies++; throw new Error('bad-proof'); }, transport: async () => new Response('1234') };
  const call = createVerifiedHttpFetch(options);
  for (const url of ['http://example.com/mcp', 'http://127.0.0.1:1234/other']) await assert.rejects(call(url, { method: 'POST', body: '{}' }), /unsupported_protected_http_request/);
  assert.equal(signs, 0);
  await assert.rejects(call(options.endpoint, { method: 'POST', body: '{}' }), /protected_response_too_large/); assert.equal(verifies, 0);
  const bad = createVerifiedHttpFetch({ ...options, maxResponseBytes: 100 });
  await assert.rejects(bad(options.endpoint, { method: 'POST', body: '{}' }), /bad-proof/);
});


test('protected fetch snapshots mutable input and aborts before dispatch after signing', async () => {
  let release!: () => void;
  const ready = new Promise<void>(resolve => { release = resolve; });
  let entered!: () => void;
  const signing = new Promise<void>(resolve => { entered = resolve; });
  const methods = ['POST'];
  let dispatched = 0;
  const call = createVerifiedHttpFetch({ endpoint: 'http://localhost/mcp', methods,
    sign: async () => { entered(); await ready; return {}; }, verify: async () => {},
    transport: async (_url, init) => { dispatched++; assert.equal(init!.body, 'original'); return new Response('ok'); } });
  const init = { method: 'POST', body: 'original' };
  const pending = call('http://localhost/mcp', init); await signing; init.body = 'tampered'; methods.push('DELETE'); release();
  assert.equal(await (await pending).text(), 'ok');
  await assert.rejects(call('http://localhost/mcp', { method: 'DELETE' }), /unsupported_protected_http_request/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(call('http://localhost/mcp', { method: 'POST', signal: controller.signal }));
  assert.equal(dispatched, 1);
});
