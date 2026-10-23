// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

/** Minimal Ubuntu host entry point. It is intentionally configuration-driven:
 * private vault paths, peer evidence and authenticated sessions are supplied by
 * the host operator and never accepted from a network caller.
 */
import { readFile } from 'node:fs/promises';
import { createAuthenticatedRuntimeIpc, listenAuthenticatedRuntimeIpc } from './verify-ipc.js';
import { RuntimeHostVerifier } from './runtime-host.js';
import { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import { SqliteBlobStore } from '../store/sqlite.js';
import { SqliteReplayStore } from '../session/index.js';

const configPath = process.argv[2];
if (!configPath) throw new Error('runtime_host_config_required');
const config = JSON.parse(await readFile(configPath, 'utf8')) as any;
for (const key of ['socketPath', 'token', 'callerId', 'identityDid', 'keyRef', 'vaultPath', 'masterKeyHex', 'peerEvidencePath', 'sessionsPath']) if (typeof config[key] !== 'string' || !config[key]) throw new Error(`runtime_host_config_missing:${key}`);
if (!/^[0-9a-fA-F]{64}$/.test(config.masterKeyHex) || config.token.length < 32) throw new Error('runtime_host_secret_invalid');
const evidence = JSON.parse(await readFile(config.peerEvidencePath, 'utf8')) as Record<string, any>;
const sessions = JSON.parse(await readFile(config.sessionsPath, 'utf8')) as any[];
const keys = new EncryptedKeyProvider(new SqliteBlobStore(config.vaultPath));
keys.unlock(Buffer.from(config.masterKeyHex, 'hex'));
const signer = await keys.getSigner(config.keyRef);
const host = new RuntimeHostVerifier(config.identityDid, signer, async did => {
  const peer = evidence[did];
  if (!peer || peer.did !== did || peer.validUntil <= Date.now()) throw new Error('evidence_unknown_or_expired');
  return peer;
}, new SqliteReplayStore(config.replayPath ?? `${config.vaultPath}.replay.sqlite`));
for (const session of sessions) await host.addVerifiedSession(session);
const server = createAuthenticatedRuntimeIpc({ token: config.token, callerId: config.callerId, tenantId: config.tenantId, verify: input => host.verify(input), sign: intent => host.sign(intent) });
await listenAuthenticatedRuntimeIpc(server, config.socketPath);
process.stdout.write(JSON.stringify({ status: 'ready', identityDid: config.identityDid, socketPath: config.socketPath }) + '\n');
await new Promise(() => {});
