// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import type { SignIntent } from '../policy/index.js';
/** Profile versions and signed execution bytes must stay bound through forwarding. */
export interface PreparedInvocation {
  protocol: SignIntent['protocol']; protocolVersion: string;
  serviceRef: string; operation: string; payload: unknown;
}
export interface ProtocolProfile {
  readonly protocol: SignIntent['protocol'];
  readonly protocolVersion: string;
  prepare(input: unknown): PreparedInvocation;
}
/** Raw request target preserves query order/duplicates and percent-encoding. */
export interface HttpInvocation {
  method: string; authority: string; requestTarget: string;
  headers: Array<[string, string]>;
  body: { kind: 'json'; value: unknown } | { kind: 'bytes'; mediaType: string; bytes: Uint8Array };
}
export interface McpInvocation {
  method: 'tools/call'; params: { name: string; arguments: Record<string, unknown> };
  toolManifestDigest: string;
}
export interface A2aInvocation { taskId: string; agentCardDigest: string; message: unknown }
/** This profile describes covered data; native protocol SDKs still validate their own schemas. */

/** Additional protocol objects must use native SDK validation before signing. */
export type McpProtocolObject = McpInvocation | {
  method: 'initialize' | 'tools/list' | 'resources/read' | 'prompts/get' | 'notifications/cancelled';
  params: unknown;
};
export interface A2aProtocolObject {
  kind: 'card' | 'message' | 'task' | 'event' | 'cancel' | 'callback' | 'artifact';
  agentCardDigest: string;
  taskId?: string;
  payload: unknown;
}
/** Registry implementations must reject unknown versions and preserve signed execution bytes.
 * Native middleware, CLI/MCP tools and sidecars share these profiles, not separate wallets.
 */
export interface ProtocolProfileRegistry {
  require(protocol: SignIntent['protocol'], protocolVersion: string): ProtocolProfile;
}
