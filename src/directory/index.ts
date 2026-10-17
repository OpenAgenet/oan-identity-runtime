// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { OanClient, DEFAULT_OAN_OFFICIAL_ENDPOINTS, type OanClientOptions } from '@openagenet/oan-sdk-ts/client';
import type { ResourceDiscoveryQuery, ResourceRegistrationSubmission, ResourceRegistrationResponse } from '@openagenet/oan-sdk-ts/protocol-types';
import type { CallerContext } from '../policy/index.js';

/** L0 only. Host configuration selects services, never per-tool arbitrary URLs. */
export class ResourceDirectory {
  private readonly client: OanClient;
  constructor(options: Pick<OanClientOptions, 'registrarEndpoint' | 'discoveryEndpoint' | 'fetchImpl'> = {}) {
    this.client = new OanClient({
      registrarEndpoint: options.registrarEndpoint ?? DEFAULT_OAN_OFFICIAL_ENDPOINTS.registrarEndpoint,
      discoveryEndpoint: options.discoveryEndpoint ?? DEFAULT_OAN_OFFICIAL_ENDPOINTS.discoveryEndpoint,
      fetchImpl: options.fetchImpl,
    });
  }
  discover(query: ResourceDiscoveryQuery) { return this.client.discoverResources(query); }
  resolve(resourceDid: string) { return this.client.getDiscoveryResource(resourceDid); }
}

/** Trusted workflow SPI, not a tool accepting private keys or pre-approved caller claims.
 * Implementations reuse SDK construction/signing and persist retry state for the same DID.
 * Approval, encrypted material storage and registration status reconciliation are required.
 */
export interface RegistrationWorkflow {
  prepare(caller: CallerContext, input: { identityRef: string; description: unknown }): Promise<{ draftId: string; resourceDid: string }>;
  submit(caller: CallerContext, draftId: string): Promise<{ resourceDid: string; response: ResourceRegistrationResponse; materialDirectory: string }>;
}
/** Host-internal client shape for workflow implementations; not an agent-facing tool. */
export interface RegistrationTransport {
  registerResource(submission: ResourceRegistrationSubmission): Promise<ResourceRegistrationResponse>;
}
