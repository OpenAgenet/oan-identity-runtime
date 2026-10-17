// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { randomUUID } from 'node:crypto';
import { canonicalJson, verifyPinnedDidDocument } from '@openagenet/oan-sdk-ts';
import type { DidDocument } from '@openagenet/oan-sdk-ts/protocol-types';
import { didOanDefaultDocumentLoader } from '@openagenet/oan-sdk-ts/protocol-types';
import { IdentityCatalog, publicIdentity, type IdentityRecord, type IdentityRepository } from '../catalog/index.js';
import type { CallerContext } from '../policy/index.js';
import type { AuditSink } from '../audit/index.js';
import type { EvidenceVerifier } from '../evidence/index.js';
import { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import { RuntimeError } from '../errors.js';
import { digestJson } from '../verification/index.js';
import type { CapabilityLease, IdentityImportBundle } from './index.js';

const CATALOG = 'host:catalog:v1';
type CatalogState = {records: IdentityRecord[]};
/** Construct and issue leases only in a trusted authenticated host, never from tool arguments. */
export class LocalIdentityVault implements IdentityRepository {
  private readonly leases = new Map<string, CapabilityLease>();
  constructor(private readonly keys: EncryptedKeyProvider, private readonly audit: AuditSink,
    private readonly evidence?: {verifier:EvidenceVerifier; rootDid:string}, private readonly now = Date.now) {}
  issueImportLease(caller: CallerContext, identityRef: string, candidateDigest: string, expiresAt: string): string {
    if (!caller.callerId || !/^[A-Za-z0-9_.-]{1,128}$/.test(identityRef) || !/^sha256:[0-9a-f]{64}$/.test(candidateDigest)
      || !Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= this.now()
      || Date.parse(expiresAt) > this.now()+300_000) throw new RuntimeError('invalid_capability_lease');
    const id=randomUUID();
    this.leases.set(id,{...structuredClone(caller), id, identityRef, candidateDigest, purpose:'identity-import',
      audienceDid:'local-vault', operation:'import', expiresAt});
    return id;
  }
  async importIdentity(caller: CallerContext, supplied: IdentityImportBundle, leaseId: string) {
    const bundle=structuredClone(supplied), bound=structuredClone(caller), lease=this.leases.get(leaseId);
    this.leases.delete(leaseId); // A lease is single use, including failed attempts.
    const check=()=>{
      if (!lease || lease.callerId!==bound.callerId || lease.tenantId!==bound.tenantId
        || lease.operation!=='import' || lease.purpose!=='identity-import' || lease.audienceDid!=='local-vault'
        || Date.parse(lease.expiresAt)<=this.now()) throw new RuntimeError('capability_lease_denied');
      return lease;
    };
    let ref='unbound';
    try {
      const granted=check(); ref=granted.identityRef;
      if (await digestJson(bundle)!==granted.candidateDigest) throw new RuntimeError('import_candidate_mismatch');
      if(!Array.isArray(bundle.sources) || bundle.sources.some(s=>!['discovery','resource-package'].includes(s.kind) || !/^https?:\/\//.test(s.uri)))throw new RuntimeError('invalid_evidence_source');
      const identity=bundle.identity, document=bundle.didDocument as DidDocument;
      if (canonicalJson(identity.didDocument)!==canonicalJson(document) || identity.did!==document.id
        || identity.verificationMethodId!==identity.did+'#key-1') throw new RuntimeError('identity_document_binding_mismatch');
      const method=Array.isArray(document.verificationMethod)?document.verificationMethod.find(m=>m?.id===identity.verificationMethodId):undefined;
      if (method?.controller!==identity.did || method.publicKeyJwk?.x!==identity.publicKeyJwk.x
        || method.publicKeyJwk?.crv!=='Ed25519' || method.publicKeyJwk?.kty!=='OKP'
        || identity.publicKeyJwk.d || identity.publicKeyJwk.kty!=='OKP' || identity.publicKeyJwk.crv!=='Ed25519'
        || identity.privateKeyJwk.kty!=='OKP' || identity.privateKeyJwk.crv!=='Ed25519' || !identity.privateKeyJwk.d
        || !Array.isArray(document.authentication) || !document.authentication.includes(identity.verificationMethodId)
        || !Array.isArray(document.assertionMethod) || !document.assertionMethod.includes(identity.verificationMethodId)) throw new RuntimeError('identity_key_binding_mismatch');
      const publicKey=await crypto.subtle.importKey('jwk',identity.publicKeyJwk as JsonWebKey,{name:'Ed25519'},false,['verify']);
      const privateKey=await crypto.subtle.importKey('jwk',identity.privateKeyJwk as JsonWebKey,{name:'Ed25519'},false,['sign']);
      const challenge=new TextEncoder().encode('oan-vault-import:'+granted.candidateDigest);
      if (!await crypto.subtle.verify('Ed25519',publicKey,await crypto.subtle.sign('Ed25519',privateKey,challenge),challenge)) throw new RuntimeError('identity_key_binding_mismatch');
      const proof=await verifyPinnedDidDocument(document,{expectedDid:identity.did,publicKeyJwk:identity.publicKeyJwk as Record<string, unknown>,
        documentLoader:async url=>url===identity.did ? {contextUrl:null,documentUrl:url,document}:didOanDefaultDocumentLoader(url)});
      if (!proof.valid) throw new RuntimeError('document_verification_failed');
      let registered=false;
      if (bundle.resourcePackage || bundle.registrationVc) {
        if (!this.evidence) throw new RuntimeError('trusted_evidence_verifier_required');
        const report=await this.evidence.verifier.verifyRegistration({didDocument:document,resourcePackage:bundle.resourcePackage,
          registrationVc:bundle.registrationVc,expectedResourceDid:identity.did,trustAnchor:{mode:'pinned-root',rootDid:this.evidence.rootDid}});
        if (!report.valid || (bundle.registrationVc !== undefined && !report.checks.some(c=>c.name==='privateVc' && c.status==='passed'))) throw new RuntimeError('registration_evidence_invalid');
        registered=true;
      }
      check();
      const existing=await this.keys.readRecord<CatalogState>(CATALOG);
      const records=existing?.value.records ?? [], catalog=new IdentityCatalog();
      for (const record of records) await catalog.add(record);
      const record:IdentityRecord={id:ref,did:identity.did,kind:document.oanMetadata?.subjectType==='controller'?'controller':'resource',
        status:registered?'registered':'local_ready',verificationMethodId:identity.verificationMethodId,keyRef:'host:key:'+ref,
        didDocument:document,evidenceRefs:bundle.resourcePackage?[bundle.resourcePackage.packageHash]:[]};
      await catalog.add(record); check();
      // Catalog, original material (including optional private VC), and signing key commit atomically.
      await this.keys.commitRecords([
        {id:CATALOG,expectedGeneration:existing?.generation??0,value:{records:[...records,record]}},
        {id:record.keyRef,expectedGeneration:0,value:{method:identity.verificationMethodId,privateJwk:identity.privateKeyJwk}},
        {id:'host:material:'+ref,expectedGeneration:0,value:bundle},
        {id:'host:audit:'+randomUUID(),expectedGeneration:0,value:{timestamp:new Date(this.now()).toISOString(),action:'identity_import',outcome:'allowed',identityRef:ref}},
      ]);
      // The authoritative import audit committed above. A secondary sink cannot turn a committed import into a reported failure.
      await this.audit.append({timestamp:new Date(this.now()).toISOString(),action:'identity_import',outcome:'allowed',identityRef:ref}).catch(()=>{});
      return publicIdentity(record);
    } catch (error) {
      const code=error instanceof RuntimeError ? error.code : 'identity_import_failed';
      await this.audit.append({timestamp:new Date(this.now()).toISOString(),action:'identity_import',outcome:'denied',identityRef:ref,code}).catch(()=>{});
      throw new RuntimeError(code);
    }
  }
  async list(): Promise<IdentityRecord[]> {return structuredClone((await this.keys.readRecord<CatalogState>(CATALOG))?.value.records??[]);}
  async get(id:string):Promise<IdentityRecord> {
    const record=(await this.list()).find(r=>r.id===id);
    if (!record) throw new RuntimeError('identity_not_found');
    return record;
  }
}
