// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/** Transport-independent tool names. No arbitrary signing or identity export tools. */
export const RUNTIME_TOOL_NAMES = ['resource.register', 'resource.discover', 'resource.resolve', 'publication.inspect', 'session.begin', 'session.accept', 'session.advance', 'invocation.execute', 'identity.list', 'identity.select', 'message.signIntent', 'message.verify', 'evidence.inspect'] as const;
export const FRAMEWORK_CAPABILITIES = {
  stage: 'framework',
  networkServer: false,
  inProcessDirectory: true,
  skillFreeToolServer: false,
  registrationWorkflow: false,
  protectedInvocation: false,
  hermesNativePlugin: false,
  mutualAuthentication: false,
  registrationTrustChain: false,
  persistentKeyProvider: false,
  plannedProfiles: ['http', 'mcp', 'a2a'],
  implementedProfiles: [],
} as const;
