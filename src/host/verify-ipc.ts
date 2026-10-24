// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { createServer, type Server } from 'node:net';
import { chmodSync, lstatSync } from 'node:fs';
import { timingSafeEqual, createHash } from 'node:crypto';
function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' || typeof value === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  throw new Error('non_json_value');
}
/** Single-request authenticated local IPC. Host callback pins trust, peer and policy.
 * Endpoint/token must be distributed through trusted process configuration; no remote TCP.
 */
export function createVerifyIpc(token: string, verify: (message: unknown) => Promise<unknown>) {
  if (Buffer.byteLength(token) < 32) throw new Error('ipc_token_too_short');
  return createServer(socket => {
    let bytes = Buffer.alloc(0), handled = false;
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', data => {
      if (handled) return;
      bytes = Buffer.concat([bytes,typeof data === 'string' ? Buffer.from(data,'utf8') : data]);
      if (bytes.length > 131072) { handled=true; socket.end('{"version":1,"ok":false,"code":"ipc_size_limit"}\n'); return; }
      if (!bytes.includes(10)) return;
      handled=true;
      void (async () => {
        let id: unknown, inputDigest: string | undefined;
        try {
          const request = JSON.parse(bytes.toString('utf8').trim()); id=request.id;
          const supplied = Buffer.from(typeof request.token === 'string' ? request.token : '');
          if (supplied.length !== Buffer.byteLength(token) || !timingSafeEqual(supplied,Buffer.from(token))) throw new Error('ipc_unauthorized');
          if (request.version !== 1 || request.operation !== 'verify' || typeof id !== 'string' || id.length > 128) throw new Error('ipc_schema_invalid');
          inputDigest='sha256:'+createHash('sha256').update(canonicalJson(request.message),'utf8').digest('hex');
          const result = await verify(structuredClone(request.message));
          socket.end(JSON.stringify({version:1,id,inputDigest,ok:true,result})+'\n');
        } catch (error) {
          const known=new Set(['ipc_unauthorized','ipc_schema_invalid','message_binding_mismatch','message_time_invalid','payload_digest_mismatch','message_signature_invalid','policy_denied','replay_detected','evidence_unknown_or_expired','registration_evidence_invalid','invalid_json_payload']);
          const code = error instanceof Error && known.has(error.message) ? error.message : 'ipc_verification_failed';
          socket.end(JSON.stringify({version:1,id:typeof id==='string' && id.length<=128?id:undefined,inputDigest,ok:false,code})+'\n');
        }
      })();
    });
  });
}

/** Versioned Runtime verifier endpoint consumed by the Rust Sidecar.
 * The socket must be protected by filesystem ownership/permissions; the bearer
 * is checked in addition to the OS boundary. Callback binding is passed to the
 * host verifier and is never accepted as a caller-provided principal.
 */
export function createAuthenticatedRuntimeIpc(options: {
  token: string;
  callerId: string;
  tenantId?: string;
  verify: (input: { envelope: unknown; audience: string; requestId: string; payloadDigest: string; callbackDid?: string }) => Promise<unknown>;
  sign?: (intent: unknown) => Promise<unknown>;
  socketMode?: number;
}) {
  if (Buffer.byteLength(options.token) < 32 || !options.callerId) throw new Error('ipc_token_or_caller_invalid');
  const server = createServer(socket => {
    let bytes = Buffer.alloc(0), handled = false;
    socket.setTimeout(5000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('data', data => {
      if (handled) return;
      bytes = Buffer.concat([bytes, Buffer.isBuffer(data) ? data : Buffer.from(data)]);
      if (bytes.length > 256 * 1024) { handled = true; socket.end(JSON.stringify({version:'oan-runtime-ipc-v1', code:'ipc_frame_too_large'})+'\n'); return; }
      if (!bytes.includes(10)) return;
      handled = true;
      void (async () => {
        let request: any;
        try {
          const newline = bytes.indexOf(10);
          if (newline < 0 || bytes.subarray(newline + 1).toString('utf8').trim() || bytes.subarray(0, newline).includes(10)) throw new Error('ipc_schema_invalid');
          request = JSON.parse(bytes.subarray(0, newline).toString('utf8'));
          // Rust Option serializes an absent callback as null; normalize only
          // this optional field before applying the same strict validation.
          if (request.callbackDid === null) delete request.callbackDid;
          // Rust's Option<String> may be encoded as either null or omitted by
          // older compatible connectors. Normalize the optional tenant before
          // applying the authenticated caller binding; never infer a tenant
          // from the network payload.
          if (request.expectedTenantId === undefined) request.expectedTenantId = null;
          const supplied = Buffer.from(typeof request.bearer === 'string' ? request.bearer : '');
          const expected = Buffer.from(options.token);
          if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected) || request.version !== 'oan-runtime-ipc-v1' || !['verify_request', 'verify_callback', 'sign_request'].includes(request.operation)) throw new Error('ipc_schema_invalid');
          if (request.operation === 'sign_request') {
            if (!options.sign || request.intent === undefined || request.expectedCallerId !== options.callerId || (request.expectedTenantId ?? null) !== (options.tenantId ?? null)) throw new Error('ipc_schema_invalid');
            const inputDigest = signInputDigest(request.intent, options.callerId, options.tenantId);
            const signed = await options.sign(structuredClone(request.intent));
            socket.end(JSON.stringify({ version:'oan-runtime-ipc-v1', callerId:options.callerId, tenantId:options.tenantId ?? null, signed, inputDigest })+'\n'); return;
          }
          if (request.envelope === undefined || typeof request.expectedAudience !== 'string' || typeof request.expectedRequestId !== 'string' || typeof request.expectedPayloadDigest !== 'string' || (request.callbackDid !== undefined && (typeof request.callbackDid !== 'string' || request.operation !== 'verify_callback'))) throw new Error('ipc_schema_invalid');
          const inputDigest = inputBindingDigest(request.envelope, request.expectedAudience, request.expectedRequestId, request.expectedPayloadDigest, request.callbackDid);
          const context = await options.verify({ envelope: structuredClone(request.envelope), audience: request.expectedAudience, requestId: request.expectedRequestId, payloadDigest: request.expectedPayloadDigest, callbackDid: request.callbackDid });
          if (!context || typeof context !== 'object') throw new Error('runtime_verification_failed');
          const suppliedContext = context as Record<string, unknown>;
          if (suppliedContext.audienceDid !== request.expectedAudience || suppliedContext.requestId !== request.expectedRequestId || suppliedContext.payloadDigest !== request.expectedPayloadDigest || (request.callbackDid !== undefined && suppliedContext.callbackDid !== request.callbackDid)) throw new Error('ipc_result_binding_mismatch');
          socket.end(JSON.stringify({ version:'oan-runtime-ipc-v1', callerId:options.callerId, tenantId:options.tenantId ?? null, context: { ...(context as object), callerId: options.callerId, tenantId: options.tenantId ?? null, ...(request.callbackDid ? { callbackDid: request.callbackDid } : {}) }, inputDigest })+'\n');
        } catch (error) {
          const known = new Set(['ipc_schema_invalid', 'ipc_result_binding_mismatch', 'runtime_verification_failed', 'policy_denied', 'replay_detected', 'evidence_unknown_or_expired', 'registration_evidence_invalid', 'message_signature_invalid', 'payload_digest_mismatch']);
          const code = error instanceof Error && known.has(error.message) ? error.message : 'runtime_verification_failed';
          socket.end(JSON.stringify({version:'oan-runtime-ipc-v1',callerId:options.callerId,tenantId:options.tenantId ?? null,code})+'\n');
        }
      })();
    });
  });
  // A Unix socket is an OS authorization boundary, not only an application
  // bearer channel. Named pipes use the local listener's restricted sharing;
  // Gateway/Sidecar also pin the Runtime process ID and present the bearer.
  server.on('listening', () => {
    const address = server.address();
    if (typeof address === 'string' && !address.startsWith('\\\\.\\pipe\\')) {
      try {
        chmodSync(address, options.socketMode ?? 0o600);
        const mode = lstatSync(address).mode & 0o777;
        if ((mode & 0o077) !== 0) server.close();
      } catch { server.close(); }
    }
  });
  return server;
}

/** Bind a local Runtime endpoint with Windows named-pipe sharing disabled by default. */
export async function listenAuthenticatedRuntimeIpc(server: Server, endpoint: string): Promise<void> {
  if (process.platform === 'win32' ? !/^\\\\\.\\pipe\\[A-Za-z0-9_.-]{1,128}$/.test(endpoint) : !endpoint.startsWith('/')) throw new Error('runtime_ipc_endpoint_invalid');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ path: endpoint, readableAll: false, writableAll: false }, () => { server.off('error', reject); resolve(); });
  });
}

function inputBindingDigest(envelope: unknown, audience: string, requestId: string, payloadDigest: string, callbackDid?: unknown) {
  const value = { envelope, audience, requestId, payloadDigest, ...(typeof callbackDid === 'string' ? { callbackDid } : {}) };
  return 'sha256:' + createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex');
}
function signInputDigest(intent: unknown, callerId: string, tenantId?: string) {
  return 'sha256:' + createHash('sha256').update(canonicalJson({ intent, callerId, tenantId: tenantId ?? null }), 'utf8').digest('hex');
}
