// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import {randomUUID} from 'node:crypto';
import type {CallerContext,SignIntent} from '../policy/index.js';
import type {IdentityRuntime,SignedMessage} from '../runtime.js';
import type {SessionManager,ReplayStore} from '../session/index.js';
import type {VerifiedPeer} from '../session/handshake.js';
import {digestJson} from '../verification/index.js';
import {verifyProtectedInvocation} from './protected.js';
import {RuntimeError} from '../errors.js';
import type {EncryptedKeyProvider} from '../key-provider/encrypted.js';

export const OAN_SECURITY_METADATA='openagenet.xyz/oan-message-v1';
export interface SynchronousProfile {
  protocol:'mcp'|'a2a'|'http';protocolVersion:string;serviceRef:string;operation:string;
  /** Public native descriptor digest pinned by host, not taken from request metadata. */
  descriptorDigest:string;
}
export interface ProtectedExchange {message:SignedMessage;result:unknown}
export interface InvocationEndpointOptions {
  identityRef:string;localDid:string;peerDid:string;runtime:IdentityRuntime;sessions:SessionManager;
  replay:ReplayStore;resolvePeer:(did:string)=>Promise<VerifiedPeer>;profile:SynchronousProfile;
  journal:EncryptedKeyProvider;
  authorize:(caller:CallerContext,payload:unknown,purpose:'request'|'response')=>Promise<void>;
}
/** Concrete synchronous boundary: sign actual protocol objects, enforce before handler,
 * verify actual response before returning. No retry after dispatch or plaintext fallback.
 */
export class SynchronousInvocation {
  private readonly profile:SynchronousProfile;
  constructor(private readonly options:InvocationEndpointOptions){
    this.profile=structuredClone(options.profile);
    if(!this.profile.serviceRef || !this.profile.operation || !this.profile.protocolVersion || !/^sha256:[a-f0-9]{64}$/.test(this.profile.descriptorDigest))throw new RuntimeError('invalid_protocol_profile');
  }
  private bound(payload:unknown){return {descriptorDigest:this.profile.descriptorDigest,object:structuredClone(payload)};}
  private operationId(requestId:string){return digestJson({localDid:this.options.localDid,peerDid:this.options.peerDid,profile:this.profile,requestId});}
  private intent(sessionId:string,requestId:string,payload:unknown,purpose:'request'|'response',requestDigest?:string):SignIntent {
    return {identityRef:this.options.identityRef,audienceDid:this.options.peerDid,purpose,protocol:this.profile.protocol,
      protocolVersion:this.profile.protocolVersion,serviceRef:this.profile.serviceRef,operation:this.profile.operation,
      sessionId,requestId,payload:this.bound(payload),...(requestDigest?{requestDigest}:{})};
  }
  async prepare(caller:CallerContext,sessionId:string,requestId:string,payload:unknown){
    const bound=structuredClone(caller),object=structuredClone(payload);
    await this.options.authorize(bound,structuredClone(object),'request');
    return this.options.runtime.signIntent(bound,this.intent(sessionId,requestId,object,'request'));
  }
  private async verify(caller:CallerContext,message:SignedMessage,payload:unknown,purpose:'request'|'response',sessionId:string,requestId:string,requestDigest?:string){
    if(!message)throw new RuntimeError('protection_required');
    await this.options.sessions.requireAuthenticatedForCaller?.(caller,sessionId,this.options.localDid,this.options.peerDid);
    return verifyProtectedInvocation(message,{localDid:this.options.localDid,peerDid:this.options.peerDid,sessionId,requestId,purpose,
      protocol:this.profile.protocol,protocolVersion:this.profile.protocolVersion,serviceRef:this.profile.serviceRef,operation:this.profile.operation,
      payload:this.bound(payload),requestDigest,sessions:this.options.sessions,replay:this.options.replay,resolvePeer:this.options.resolvePeer,
      authorize:()=>this.options.authorize(structuredClone(caller),structuredClone(payload),purpose)});
  }
  async receive(caller:CallerContext,request:SignedMessage,payload:unknown,handler:(actual:unknown)=>Promise<unknown>):Promise<ProtectedExchange>{
    const bound=structuredClone(caller),message=structuredClone(request),actual=structuredClone(payload);
    if(!message?.context)throw new RuntimeError('protection_required');
    const checked=await this.verify(bound,message,actual,'request',message.context.sessionId,message.context.requestId);
    const id='invocation:'+await this.operationId(message.context.requestId);
    const previous=await this.options.journal.readRecord<{digest:string}>(id);
    if(previous)throw new RuntimeError(previous.value.digest===await digestJson(actual)?'operation_already_submitted':'operation_id_conflict');
    const record={owner:bound,digest:await digestJson(actual),state:'unknown',requestDigest:checked.requestDigest};
    await this.options.journal.commitRecords([{id,expectedGeneration:0,value:record}]);
    // A handler cannot be reached until signature, evidence, scope, replay and policy succeed.
    // Its protocol error result is signed with the same request correlation as a success.
    const result=await handler(structuredClone(actual));
    const response=await this.options.runtime.signIntent(bound,this.intent(message.context.sessionId,message.context.requestId,result,'response',checked.requestDigest));
    await this.options.journal.commitRecords([{id,expectedGeneration:1,value:{...record,state:'completed',exchange:{result,message:response}}}]);
    return {result:structuredClone(result),message:response};
  }
  async inspect(caller:CallerContext,requestId:string):Promise<{state:'not_found'|'unknown'|'completed';exchange?:ProtectedExchange}>{
    const bound=structuredClone(caller),row=await this.options.journal.readRecord<{owner:CallerContext;state:'unknown'|'completed';exchange?:ProtectedExchange}>('invocation:'+await this.operationId(requestId));
    if(!row)return {state:'not_found'};
    if(row.value.owner.callerId!==bound.callerId || row.value.owner.tenantId!==bound.tenantId)throw new RuntimeError('invocation_access_denied');
    await this.options.authorize(bound,{},'response');
    return {state:row.value.state,...(row.value.exchange?{exchange:row.value.exchange}:{})};
  }
  async acceptResponse(caller:CallerContext,request:SignedMessage,response:ProtectedExchange){
    const bound=structuredClone(caller),original=structuredClone(request),reply=structuredClone(response);
    // The expected request is the actual client-created object, never a response-provided reference.
    await this.verify(bound,reply.message,reply.result,'response',original.context.sessionId,original.context.requestId,await digestJson(original));
    return {result:reply.result,registrationTrust:'verified_pinned_root' as const};
  }
  async execute(caller:CallerContext,input:{sessionRef:string;payload:unknown;requestId?:string},dispatch:(request:SignedMessage,actual:unknown)=>Promise<ProtectedExchange>){
    const bound=structuredClone(caller),actual=structuredClone(input.payload),request=await this.prepare(bound,input.sessionRef,input.requestId??randomUUID(),actual);
    let response:ProtectedExchange;
    try{response=await dispatch(request,structuredClone(actual));}
    catch{throw new RuntimeError('invocation_result_unknown');}
    return this.acceptResponse(bound,request,response);
  }
}

/** Native carrier helpers strip only OAN's reserved field, preserving other metadata/auth. */
export function attachOanMetadata<T extends Record<string,unknown>>(object:T,field:'_meta'|'metadata',message:SignedMessage):T {
  const result=structuredClone(object),metadata=result[field];
  if(metadata!==undefined && (!metadata || typeof metadata!=='object' || Array.isArray(metadata)))throw new RuntimeError('invalid_protocol_metadata');
  if(metadata && Object.hasOwn(metadata,OAN_SECURITY_METADATA))throw new RuntimeError('reserved_identity_metadata');
  return {...result,[field]:{...(metadata as Record<string,unknown>??{}),[OAN_SECURITY_METADATA]:structuredClone(message)}};
}
export function detachOanMetadata<T extends Record<string,unknown>>(object:T,field:'_meta'|'metadata'):{object:T;message:SignedMessage} {
  const result=structuredClone(object),meta=result[field] as Record<string,unknown>|undefined;
  if(!meta || !Object.hasOwn(meta,OAN_SECURITY_METADATA))throw new RuntimeError('protection_required');
  const message=meta[OAN_SECURITY_METADATA] as SignedMessage;delete meta[OAN_SECURITY_METADATA];
  if(!Object.keys(meta).length)delete result[field];
  return {object:result,message};
}
