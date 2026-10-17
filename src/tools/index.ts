// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/** Planned transport-independent tool names; not installed handlers. No arbitrary signing or identity export tools. */
export const RUNTIME_TOOL_NAMES = ['resource.register', 'resource.discover', 'resource.resolve', 'publication.inspect', 'session.begin', 'session.accept', 'session.advance', 'session.inspect', 'session.close', 'identity.verification.begin', 'identity.verification.accept', 'identity.verification.advance', 'identity.verification.inspect', 'identity.verification.close', 'invocation.execute', 'identity.list', 'identity.select', 'message.signIntent', 'message.verify', 'evidence.inspect'] as const;
export const FRAMEWORK_CAPABILITIES = {
  stage: 'g0-g4-synchronous',
  networkServer: false,
  inProcessDirectory: true,
  skillFreeToolServer: true,
  registrationWorkflow: true,
  protectedInvocation: true,
  hermesNativePlugin: false,
  mutualAuthentication: true,
  identityVerification: { contractVersion: 1, profile: 'oan-session-v1', workflow: true, transports: ['skill', 'cli', 'mcp'], requiresSidecar: false, businessProtection: true },
  registrationTrustChain: false,
  persistentKeyProvider: true,
  plannedProfiles: ['http', 'mcp', 'a2a'],
  implementedProfiles: ['http', 'mcp', 'a2a'],
} as const;
