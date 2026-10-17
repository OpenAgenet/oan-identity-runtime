// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { randomUUID } from 'node:crypto';
import type { CallerContext } from '../policy/index.js';
import type { RegistrationWorkflow } from '../directory/index.js';
import type { EncryptedKeyProvider } from '../key-provider/encrypted.js';
import type { ResourceRegistrationResponse } from '@openagenet/oan-sdk-ts/protocol-types';
import { digestJson } from '../verification/index.js';
import { RuntimeError } from '../errors.js';
import { observePublication, type PublicationAttempt, type PublicationObservation } from './index.js';

export interface PreparedRegistration {resourceDid:string;candidate:unknown}
export interface PublicationBackend {
  /** Reuse SDK/Skill construction. Input paths and identities are resolved by the trusted host. */
  prepare(identityRef:string,description:unknown):Promise<PreparedRegistration>;
  submit(candidate:unknown,idempotencyKey:string):Promise<{response:ResourceRegistrationResponse;materialDirectory:string}>;
  reconcile(attempt:PublicationAttempt,candidate:unknown):Promise<PublicationObservation>;
  /** Read-only recovery of local materials/receipt after a confirmed timeout. Must not submit. */
  recoverResult?(attempt:PublicationAttempt,candidate:unknown):Promise<{response:ResourceRegistrationResponse;materialDirectory:string}>;
}
interface Entry {owner:CallerContext;identityRef:string;inputDigest:string;candidate:unknown;attempt:PublicationAttempt;previousResourceDid?:string;result?:{response:ResourceRegistrationResponse;materialDirectory:string}}
/** Encrypted crash-safe journal. Submitted/uncertain operations NEVER automatically resubmit. */
export class DurableRegistrationWorkflow implements RegistrationWorkflow {
  constructor(private readonly keys:EncryptedKeyProvider,private readonly backend:PublicationBackend,
    private readonly approve:(caller:CallerContext,input:{identityRef:string;resourceDid:string;candidateDigest:string;operation:'prepare'|'publish'})=>Promise<boolean>){}
  private id(caller:CallerContext,ref:string){return 'publication:'+JSON.stringify([caller.callerId,caller.tenantId??null,ref]);}
  private async read(caller:CallerContext,draftId:string){
    const row=await this.keys.readRecord<Entry>(draftId);
    if(!row || row.value.owner.callerId!==caller.callerId || row.value.owner.tenantId!==caller.tenantId)throw new RuntimeError('publication_access_denied');
    return row;
  }
  private public(entry:Entry){return {...entry.attempt,identityRef:entry.identityRef};}
  async prepare(caller:CallerContext,input:{identityRef:string;description:unknown}){
    if(!/^[A-Za-z0-9_.-]{1,128}$/.test(input.identityRef))throw new RuntimeError('invalid_identity_ref');
    const bound=structuredClone(caller),description=structuredClone(input.description),digest=await digestJson(description);
    const draftId=this.id(bound,input.identityRef),old=await this.keys.readRecord<Entry>(draftId);
    if(old && old.value.attempt.state!=='registered'){
      if(!old.value.attempt.resourceDid)throw new RuntimeError('publication_preparation_incomplete');
      if(old.value.inputDigest!==digest)throw new RuntimeError('publication_candidate_conflict');
      return {draftId,resourceDid:old.value.attempt.resourceDid};
    }
    if(old?.value.inputDigest===digest)return {draftId,resourceDid:old.value.attempt.resourceDid};
    if(!await this.approve(bound,{identityRef:input.identityRef,resourceDid:'',candidateDigest:digest,operation:'prepare'}))throw new RuntimeError('publication_approval_required');
    // Claim before identity generation: crashes/concurrent prepares cannot create orphan replacement DIDs.
    const claim={owner:bound,identityRef:input.identityRef,inputDigest:digest,candidate:null,previousResourceDid:old?.value.attempt.resourceDid,
      attempt:{attemptId:randomUUID(),resourceDid:'',candidateDigest:digest,idempotencyKey:randomUUID(),state:'candidate' as const}};
    await this.keys.commitRecords([{id:draftId,expectedGeneration:old?.generation??0,value:claim}]);
    let prepared:PreparedRegistration;
    try {
      prepared=await this.backend.prepare(input.identityRef,description);
      if(!prepared.resourceDid || (old && old.value.attempt.resourceDid!==prepared.resourceDid))throw new RuntimeError('publication_candidate_invalid');
    } catch(error) {
      // A failed update must not erase the last successful DID/candidate. A first preparation
      // stays claimed for host recovery, since identity generation may already have happened.
      if(old)await this.keys.commitRecords([{id:draftId,expectedGeneration:old.generation+1,value:old.value}]);
      throw error instanceof RuntimeError ? error : new RuntimeError('publication_preparation_incomplete');
    }
    const entry:Entry={...claim,candidate:structuredClone(prepared.candidate),attempt:{...claim.attempt,resourceDid:prepared.resourceDid,candidateDigest:await digestJson(prepared.candidate)}};
    await this.keys.commitRecords([{id:draftId,expectedGeneration:(old?.generation??0)+1,value:entry}]);
    return {draftId,resourceDid:prepared.resourceDid};
  }
  async submit(caller:CallerContext,draftId:string){
    const row=await this.read(caller,draftId),entry=row.value;
    if(!entry.candidate || !entry.attempt.resourceDid)throw new RuntimeError('publication_preparation_incomplete');
    if(entry.attempt.state==='registered'){
      if(!entry.result && this.backend.recoverResult){
        entry.result=await this.backend.recoverResult(structuredClone(entry.attempt),structuredClone(entry.candidate));
        await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation,value:entry}]);
      }
      if(entry.result)return {resourceDid:entry.attempt.resourceDid,...entry.result};
      throw new RuntimeError('publication_material_recovery_required');
    }
    if(entry.attempt.state!=='candidate')throw new RuntimeError('publication_reconciliation_required');
    if(!await this.approve(structuredClone(caller),{identityRef:entry.identityRef,resourceDid:entry.attempt.resourceDid,candidateDigest:entry.attempt.candidateDigest,operation:'publish'}))throw new RuntimeError('publication_approval_required');
    entry.attempt.state='submitted';
    await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation,value:entry}]);
    let result:Entry['result'];
    try{result=await this.backend.submit(structuredClone(entry.candidate),entry.attempt.idempotencyKey);}
    catch{
      entry.attempt.state='uncertain';
      await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation+1,value:entry}]);
      throw new RuntimeError('publication_reconciliation_required');
    }
    entry.result=result;
    await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation+1,value:entry}]);
    // A successful HTTP response is not sufficient: reconcile DID, digest/version and source.
    entry.attempt=observePublication(entry.attempt,await this.backend.reconcile(structuredClone(entry.attempt),structuredClone(entry.candidate)));
    await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation+2,value:entry}]);
    if(entry.attempt.state!=='registered')throw new RuntimeError('publication_reconciliation_required');
    return {resourceDid:entry.attempt.resourceDid,...result!};
  }
  async inspect(caller:CallerContext,draftId:string){
    const row=await this.read(caller,draftId),entry=row.value;
    if(['submitted','uncertain'].includes(entry.attempt.state)){
      entry.attempt=observePublication(entry.attempt,await this.backend.reconcile(structuredClone(entry.attempt),structuredClone(entry.candidate)));
      await this.keys.commitRecords([{id:draftId,expectedGeneration:row.generation,value:entry}]);
    }
    return this.public(entry);
  }
}
