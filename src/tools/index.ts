// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/** Planned transport-independent tool names; not installed handlers. No arbitrary signing or identity export tools. */
export const RUNTIME_TOOL_NAMES = ['resource.register', 'resource.discover', 'resource.resolve', 'publication.inspect', 'session.begin', 'session.accept', 'session.advance', 'session.inspect', 'session.close', 'identity.verification.begin', 'identity.verification.accept', 'identity.verification.advance', 'identity.verification.inspect', 'identity.verification.close', 'invocation.execute', 'identity.list', 'identity.select', 'message.signIntent', 'message.verify', 'evidence.inspect'] as const;
export const FRAMEWORK_CAPABILITIES = {
  stage: 'framework',
  networkServer: false,
  inProcessDirectory: true,
  skillFreeToolServer: false,
  registrationWorkflow: false,
  protectedInvocation: false,
  hermesNativePlugin: false,
  mutualAuthentication: false,
  identityVerification: { contractVersion: 1, profile: 'oan-session-v1', workflow: false, transports: ['skill', 'cli', 'mcp'], requiresSidecar: false, businessProtection: false },
  registrationTrustChain: false,
  persistentKeyProvider: false,
  plannedProfiles: ['http', 'mcp', 'a2a'],
  implementedProfiles: [],
} as const;
