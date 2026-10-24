// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { createActorNativeHttpFetch } from '../dist/index.js';

// Trusted local module supplies route + registered actor + verified session.
// It is never selected by peer input. No demo topology or control API required.
export function nativeClientFetch(trustedHostOptions) {
  return createActorNativeHttpFetch(trustedHostOptions);
}
if (process.argv[2]) {
  const { createClientOptions } = await import(pathToFileURL(resolve(process.argv[2])).href);
  const options = await createClientOptions();
  const protectedFetch = nativeClientFetch(options);
  // Pass this fetch hook to your native protocol SDK. This example deliberately
  // makes no business request, selects no peer and grants no permissions.
  console.log(JSON.stringify({ configured: typeof protectedFetch === 'function', endpoint: options.endpoint }));
}
