// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { createServer } from 'node:net';
import { timingSafeEqual, createHash } from 'node:crypto';
import { canonicalJson } from '@openagenet/oan-sdk-ts';
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
