// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import test from 'node:test';
import assert from 'node:assert/strict';
import { ResourceDirectory, FRAMEWORK_CAPABILITIES, RUNTIME_TOOL_NAMES } from '../src/index.js';

test('skill-free directory uses official discovery and preserves SDK wire queries', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const directory = new ResourceDirectory({ fetchImpl: async (input, init) => {
    calls.push({ url: String(input), init });
    return new Response(JSON.stringify({ resourceDid: 'did:oan:test', candidates: [] }), { status: 200 });
  } });
  const query = { resourceType: 'skill' as const, query: 'search', protocol: 'mcp', limit: 2 };
  await directory.discover(query);
  await directory.resolve('did:oan:test');
  assert.equal(calls[0].url, 'https://discovery.openagenet.xyz/discovery/resources/query');
  assert.deepEqual(JSON.parse(String(calls[0].init?.body)), query);
  assert.equal(calls[1].url, 'https://discovery.openagenet.xyz/discovery/index/resources/did%3Aoan%3Atest');
});

test('third-party directory configuration works and network errors are not authentication success', async () => {
  const directory = new ResourceDirectory({ discoveryEndpoint: 'https://directory.example', fetchImpl: async input => {
    assert.equal(String(input), 'https://directory.example/discovery/resources/query');
    return new Response('{}', { status: 503 });
  } });
  await assert.rejects(directory.discover({}), /503/);
  assert.equal(FRAMEWORK_CAPABILITIES.mutualAuthentication, false);
  assert.equal(FRAMEWORK_CAPABILITIES.protectedInvocation, false);
  assert.equal(FRAMEWORK_CAPABILITIES.registrationWorkflow, false);
  assert.ok(RUNTIME_TOOL_NAMES.includes('resource.register'));
  assert.ok(RUNTIME_TOOL_NAMES.includes('invocation.execute'));
});
