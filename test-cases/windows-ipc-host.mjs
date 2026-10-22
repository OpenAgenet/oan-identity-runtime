// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
// Cross-language fixture: invoked by Gateway and Sidecar Windows connector tests.
import { createAuthenticatedRuntimeIpc, listenAuthenticatedRuntimeIpc } from '../dist/host/verify-ipc.js';

const [endpoint, token, callerId, tenantId] = process.argv.slice(2);
if (!endpoint || !token || !callerId) throw new Error('fixture_configuration_invalid');
const server = createAuthenticatedRuntimeIpc({
  token, callerId, tenantId: tenantId === '-' ? undefined : tenantId,
  verify: async ({ audience, requestId, payloadDigest, callbackDid }) => ({
    subjectDid: 'did:oan:fixture', audienceDid: audience, requestId, payloadDigest,
    ...(callbackDid ? { callbackDid } : {}),
  }),
  sign: async intent => ({ fixtureSigned: true, intent }),
});
await listenAuthenticatedRuntimeIpc(server, endpoint);
process.stdout.write('READY\n');
