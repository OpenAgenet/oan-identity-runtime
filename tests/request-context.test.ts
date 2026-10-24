// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { snapshotRequestScope, requireNativeHttpBinding } from '../src/host/request-context.js';

test('host context rejects malformed values, protocol overrides and conflicting compatibility bindings', () => {
  for (const requestContext of [null, [], 'text', { rawBodyDigest: 'override' }, { tenantId: 'other' }, { constructor: 'override' }, { x: '' }, { x: 1 }, new Date()]) {
    assert.throws(() => snapshotRequestScope({ tenantId: 'workspace', requestContext: requestContext as any }), /invalid_host_request_context/);
  }
  assert.throws(() => snapshotRequestScope({ tenantId: 'workspace', runId: 'a', requestContext: { runId: 'b' } }), /invalid_host_request_context/);
  assert.throws(() => snapshotRequestScope({ tenantId: 'workspace', requireHttpBinding: 'false' as any }), /invalid_host_request_context/);
  const original = { environment: 'production' };
  const scope = snapshotRequestScope({ tenantId: 'workspace', requestContext: original, requireHttpBinding: true });
  original.environment = 'other'; assert.equal(scope.requestContext!.environment, 'production');
  assert.throws(() => { (scope.requestContext as any).environment = 'other'; }, TypeError);
  assert.equal(snapshotRequestScope({ tenantId: 'workspace', runId: 'legacy' }).requireHttpBinding, true);
});

test('HTTP-bound signer rejects incomplete binding before an operation can be signed', () => {
  for (const binding of [undefined, {}, { method: '', target: '/mcp', mcpSessionId: '' }, { method: 'POST', target: '//other-host', mcpSessionId: '' }]) {
    assert.throws(() => requireNativeHttpBinding(binding), /http_request_binding_required/);
  }
  requireNativeHttpBinding({ method: 'POST', target: '/mcp?query=1', mcpSessionId: '' });
});
