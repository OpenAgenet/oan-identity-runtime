// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import {parseDidOan} from '@openagenet/oan-sdk-ts';
import type {IdentityRepository} from '../catalog/index.js';
import type {SigningKeyResolver} from '../key-provider/index.js';
import type {EncryptedKeyProvider} from '../key-provider/encrypted.js';
import type {CallerContext} from '../policy/index.js';
import type {AuditSink} from '../audit/index.js';
import {digestJson} from '../verification/index.js';
import {RuntimeError} from '../errors.js';
import {MutualHandshake,type HandshakeState,type HandshakeMessage,type VerifiedPeer} from './handshake.js';
import type {IdentityVerificationWorkflow,IdentityVerificationScope,IdentityVerificationStatus,PublicIdentityHandshakeMessage,SessionManager} from './index.js';

interface Entry {
  owner:CallerContext; input:IdentityVerificationScope; localDid:string; state:HandshakeState;
  ownBinding:string; peerBinding:string; closed:boolean;
}
export interface VerificationWorkflowOptions {
  store:EncryptedKeyProvider;catalog:IdentityRepository;keys:SigningKeyResolver;audit:AuditSink;
  resolvePeer:(did:string)=>Promise<VerifiedPeer>;
  /** Host-owned identity/peer/scope policy, applied again on every operation and recovery. */
  authorize:(caller:CallerContext,input:IdentityVerificationScope)=>Promise<void>;
}
function publicMessage(message:HandshakeMessage):PublicIdentityHandshakeMessage {
  return {profile:'oan-session-v1',kind:message.body.kind,body:structuredClone(message.body),jws:message.jws};
}
function wire(value:PublicIdentityHandshakeMessage):HandshakeMessage {
  try {
    const text=JSON.stringify(value);
    if(!text || text.length>16384 || /"(?:privateKey[^" ]*|secretKey|seed)"\s*:/i.test(text))throw new Error();
    const m=structuredClone(value),b=m.body as HandshakeMessage['body'];
    if(Object.keys(m).some(k=>!['profile','kind','body','jws'].includes(k)))throw new Error();
    if(!b || m.profile!=='oan-session-v1' || m.kind!==b.kind || typeof m.jws!=='string'
      || typeof b.sessionId!=='string' || !/^[a-zA-Z0-9-]{1,128}$/.test(b.sessionId))throw new Error();
    return {body:b,jws:m.jws};
  }catch{throw new RuntimeError('invalid_handshake_message');}
}
/** Durable, encrypted, caller-scoped user workflow. No model/tool can import trusted state. */
export class DurableIdentityVerification implements IdentityVerificationWorkflow,SessionManager {
  constructor(private readonly options:VerificationWorkflowOptions){}
  private id(ref:string){if(!/^[a-zA-Z0-9-]{1,128}$/.test(ref))throw new RuntimeError('session_not_found');return 'session:v1:'+ref;}
  private async binding(did:string){
    const peer=await this.options.resolvePeer(did);
    if(peer.did!==did || !Number.isFinite(peer.validUntil) || peer.validUntil<=Date.now()
      || peer.publicKeyJwk.d || peer.publicKeyJwk.kty!=='OKP' || peer.publicKeyJwk.crv!=='Ed25519')throw new RuntimeError('evidence_unknown_or_expired');
    return digestJson({did,verificationMethod:peer.verificationMethod,publicKeyJwk:peer.publicKeyJwk,...(peer.evidenceBinding?{evidenceBinding:peer.evidenceBinding}:{})});
  }
  private async engine(entry:Entry,caller:CallerContext){
    await this.options.authorize(structuredClone(caller),structuredClone(entry.input));
    const identity=await this.options.catalog.get(entry.input.identityRef);
    if(identity.did!==entry.localDid || identity.status!=='registered')throw new RuntimeError('identity_not_ready_for_business_signing');
    if(await this.binding(entry.localDid)!==entry.ownBinding || await this.binding(entry.input.peerDid)!==entry.peerBinding)throw new RuntimeError('session_evidence_changed');
    const signer=await this.options.keys.resolve(identity.keyRef,'challenge');
    if(signer.keyId!==identity.verificationMethodId || (await signer.publicKey()).x!==identity.didDocument.verificationMethod?.find(m=>m.id===signer.keyId)?.publicKeyJwk?.x)throw new RuntimeError('identity_key_binding_mismatch');
    return new MutualHandshake(identity.did,signer,this.options.resolvePeer);
  }
  private async read(caller:CallerContext,ref:string){
    const bound=structuredClone(caller),row=await this.options.store.readRecord<Entry>(this.id(ref));
    if(!row || row.value.owner.callerId!==bound.callerId || row.value.owner.tenantId!==bound.tenantId)throw new RuntimeError('session_access_denied');
    return row;
  }
  private async create(caller:CallerContext,supplied:IdentityVerificationScope,message?:PublicIdentityHandshakeMessage){
    const owner=structuredClone(caller),input=structuredClone(supplied),incoming=message?wire(message):undefined;
    const fields=['identityRef','peerDid','purpose','scope','profile','serviceRef','protocol','protocolVersion'];
    if(!input || Object.keys(input).some(k=>!fields.includes(k)) || fields.some(k=>typeof input[k as keyof IdentityVerificationScope]!=='string' || !input[k as keyof IdentityVerificationScope])
      || !owner.callerId || input.profile!=='oan-session-v1'
      || !['mcp','a2a','http'].includes(input.protocol) || !input.protocolVersion || JSON.stringify(input).length>8192)throw new RuntimeError('invalid_verification_scope');
    parseDidOan(input.peerDid);
    await this.options.authorize(structuredClone(owner),structuredClone(input));
    const identity=await this.options.catalog.get(input.identityRef);
    const entry:Entry={owner,input,localDid:identity.did,state:undefined as any,closed:false,
      ownBinding:await this.binding(identity.did),peerBinding:await this.binding(input.peerDid)};
    const engine=await this.engine(entry,owner);
    const scope={initiatorDid:incoming?input.peerDid:identity.did,responderDid:incoming?identity.did:input.peerDid,
      serviceRef:input.serviceRef,protocol:input.protocol,protocolVersion:input.protocolVersion,
      verificationPurpose:input.purpose,verificationScope:input.scope};
    const outgoing=incoming?await engine.accept(scope,incoming):await engine.begin(scope),ref=outgoing.body.sessionId;
    entry.state=engine.snapshot(ref);
    await this.options.store.commitRecords([{id:this.id(ref),expectedGeneration:0,value:entry}]);
    await this.audit(input.identityRef,'pending');
    return {sessionRef:ref,outgoing:publicMessage(outgoing)};
  }
  begin(caller:CallerContext,input:IdentityVerificationScope){return this.create(caller,input);}
  accept(caller:CallerContext,input:IdentityVerificationScope,message:PublicIdentityHandshakeMessage){return this.create(caller,input,message);}
  async advance(caller:CallerContext,ref:string,supplied:PublicIdentityHandshakeMessage){
    const bound=structuredClone(caller),message=wire(supplied),row=await this.read(bound,ref),entry=row.value;
    if(entry.closed)throw new RuntimeError('session_closed');
    const engine=await this.engine(entry,bound);engine.restore(ref,entry.state);
    const result=await engine.advance(ref,message);entry.state=engine.snapshot(ref);
    await this.options.store.commitRecords([{id:this.id(ref),expectedGeneration:row.generation,value:entry}]);
    const status=await this.inspect(bound,ref);await this.audit(entry.input.identityRef,status.state);
    return {status,...(result.reply?{outgoing:publicMessage(result.reply)}:{})};
  }
  async inspect(caller:CallerContext,ref:string):Promise<IdentityVerificationStatus>{
    const bound=structuredClone(caller),{value:entry}=await this.read(bound,ref);
    await this.options.authorize(bound,structuredClone(entry.input));
    let state:IdentityVerificationStatus['state']=entry.closed?'closed':Date.parse(entry.state.last.body.expiresAt)<=Date.now()?'expired':'pending';
    if(state==='pending'){
      const engine=await this.engine(entry,bound);engine.restore(ref,entry.state);
      if(entry.state.stage==='completed'){await engine.requireAuthenticated(ref,entry.localDid,entry.input.peerDid);state='completed';}
    }
    const peer=state==='completed'?await this.options.resolvePeer(entry.input.peerDid):undefined;
    return {sessionRef:ref,localDid:entry.localDid,peerDid:entry.input.peerDid,purpose:entry.input.purpose,scope:entry.input.scope,
      expiresAt:entry.state.last.body.expiresAt,state,evidence:peer?.evidenceChecks?.map(c=>({name:c.name,status:c.status,...(c.source?{source:c.source}:{})}))
        ?? [{name:'registrationTrust',status:state==='completed'?'valid':'unknown',source:'host-verified-pinned-root'},
          {name:'liveGovernance',status:'unknown'},{name:'liveRevocation',status:'unknown'}],
      peerPossession:state==='completed'?'valid':'not_checked',peerConfirmation:state==='completed'?'verified':'pending',businessProtection:'not_established',
      ...((state==='pending' || state==='completed') && !(entry.state.stage==='completed' && entry.state.role==='initiator')?{outgoing:publicMessage(entry.state.last)}:{})};
  }
  async close(caller:CallerContext,ref:string){
    const bound=structuredClone(caller),row=await this.read(bound,ref);await this.options.authorize(bound,structuredClone(row.value.input));
    row.value.closed=true;await this.options.store.commitRecords([{id:this.id(ref),expectedGeneration:row.generation,value:row.value}]);
    await this.audit(row.value.input.identityRef,'closed');
  }
  /** Trusted Runtime path only; tool callers use the caller-scoped inspect API. */
  async requireAuthenticatedForCaller(caller:CallerContext,ref:string,localDid:string,peerDid:string){
    await this.read(caller,ref);
    return this.requireAuthenticated(ref,localDid,peerDid);
  }
  async requireAuthenticated(ref:string,localDid:string,peerDid:string){
    const row=await this.options.store.readRecord<Entry>(this.id(ref)),entry=row?.value;
    if(!entry || entry.closed || entry.localDid!==localDid || entry.input.peerDid!==peerDid)throw new RuntimeError('session_not_authenticated');
    const engine=await this.engine(entry,entry.owner);engine.restore(ref,entry.state);
    return engine.requireAuthenticated(ref,localDid,peerDid);
  }
  private async audit(identityRef:string,state:string){
    await this.options.audit.append({timestamp:new Date().toISOString(),action:'identity_verification',identityRef,outcome:'allowed',code:state}).catch(()=>{});
  }
}
