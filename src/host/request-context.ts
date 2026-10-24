// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { RuntimeError } from '../errors.js';

export interface HostRequestScope {
  /** Legacy application binding alias. */
  runId?: string;
  tenantId: string;
  requestContext?: Readonly<Record<string, string>>;
  requireHttpBinding?: boolean;
}

/** Host startup configuration only. Bounded, immutable and free of protocol
 * overrides; applications choose opaque values, Runtime only compares them. */
export function snapshotRequestScope(scope: HostRequestScope): Readonly<HostRequestScope> {
  const invalid = () => { throw new RuntimeError('invalid_host_request_context'); };
  if (!scope || typeof scope.tenantId !== 'string' || !scope.tenantId.trim()
    || (scope.runId !== undefined && (typeof scope.runId !== 'string' || !scope.runId.trim()))
    || (scope.requireHttpBinding !== undefined && typeof scope.requireHttpBinding !== 'boolean')) invalid();
  const context = scope.requestContext;
  if (context !== undefined && (!context || typeof context !== 'object' || Array.isArray(context)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(context)))) invalid();
  const entries = Object.entries(context ?? {});
  if (entries.length > 32 || entries.some(([key, value]) => !key.trim() || key.length > 128
    || ['rawBodyDigest', 'httpBinding', 'tenantId', '__proto__', 'constructor', 'prototype'].includes(key)
    || typeof value !== 'string' || !value.trim() || value.length > 4096)
    || (scope.runId !== undefined && context?.runId !== undefined && context.runId !== scope.runId)) invalid();
  const requestContext = Object.freeze(Object.fromEntries(entries));
  return Object.freeze({ tenantId: scope.tenantId, runId: scope.runId,
    requestContext, requireHttpBinding: scope.requireHttpBinding ?? Boolean(scope.runId) });
}

export interface NativeHttpBinding { method: string; target: string; mcpSessionId: string }
export function requireNativeHttpBinding(binding: unknown): asserts binding is NativeHttpBinding {
  const value = binding as NativeHttpBinding | null;
  if (!value || typeof value.method !== 'string' || !value.method.trim()
    || typeof value.target !== 'string' || !value.target.startsWith('/') || value.target.startsWith('//')
    || typeof value.mcpSessionId !== 'string') throw new RuntimeError('http_request_binding_required');
}
