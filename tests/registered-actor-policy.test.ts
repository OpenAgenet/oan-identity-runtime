// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import { registeredActorPolicy } from '../src/host/registered-actor.js';
import type { PolicyRule, SignIntent } from '../src/policy/index.js';

const intent: SignIntent = { identityRef: 'actor', audienceDid: 'did:oan:test:peer', purpose: 'request', protocol: 'mcp', operation: 'tools/call', protocolVersion: '2025-11-25', serviceRef: 'service', sessionId: 'session', requestId: 'request', payload: {} };
test('registered actor preserves legacy caller, tenant and per-request policy defaults', async () => {
  const config = registeredActorPolicy({ identityRef: 'actor' });
  assert.deepEqual(config.caller, { callerId: 'actor', tenantId: 'oan-reference' });
  await config.forRequest(intent.audienceDid, 'mcp', 'tools/call').authorize(config.caller, intent);
});
test('registered actor trusted tenant and allowlist are isolated, snapshotted and fail closed', async () => {
  const rule: PolicyRule = { callerId: 'host', tenantId: 'team', identityRef: 'actor', audienceDid: intent.audienceDid, purpose: 'request', protocol: 'mcp', operation: 'tools/call' };
  const config = registeredActorPolicy({ identityRef: 'actor', callerId: 'host', tenantId: 'team', policyRules: [rule] });
  rule.operation = 'other';
  const policy = config.forRequest(intent.audienceDid, 'mcp', 'tools/call');
  await policy.authorize(config.caller, intent);
  await assert.rejects(policy.authorize({ ...config.caller, tenantId: 'other' }, intent), /policy_denied/);
  await assert.rejects(policy.authorize(config.caller, { ...intent, operation: 'other' }), /policy_denied/);
  await assert.rejects(policy.authorize(config.caller, { ...intent, audienceDid: 'did:oan:test:other' }), /policy_denied/);
  await assert.rejects(registeredActorPolicy({ identityRef: 'actor', policyRules: [] }).forRequest(intent.audienceDid, 'mcp', 'tools/call').authorize({ callerId: 'actor', tenantId: 'oan-reference' }, intent), /policy_denied/);
  assert.throws(() => registeredActorPolicy({ identityRef: 'actor', tenantId: ' ' }), /runtime_actor_context_invalid/);
  assert.throws(() => { (config.caller as { tenantId: string }).tenantId = 'other'; }, TypeError);
  for (const invalid of [null, {}, [null], [{ ...rule, operation: '' }], [{ ...rule, protocol: 'other' }]]) {
    assert.throws(() => registeredActorPolicy({ identityRef: 'actor', policyRules: invalid as any }), /runtime_actor_policy_invalid/);
  }
});
