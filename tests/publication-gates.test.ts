// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {DurableRegistrationWorkflow,EncryptedKeyProvider} from '../src/index.js';
import type {PublicationBackend} from '../src/index.js';
import {SqliteBlobStore} from '../src/store/sqlite.js';

const owner={callerId:'owner',tenantId:'tenant-a'};
function setup(overrides:Partial<PublicationBackend>={},approve:ConstructorParameters<typeof DurableRegistrationWorkflow>[2]=async()=>true){
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store);keys.unlock(randomBytes(32));
  let prepares=0,submits=0;
  const backend:PublicationBackend={
    async prepare(ref,description){prepares++;return {resourceDid:'did:oan:stable',candidate:{ref,description}};},
    async submit(){submits++;return {response:{} as any,materialDirectory:'private/materials'};},
    async reconcile(attempt){return {kind:'confirmed',evidence:{resourceDid:attempt.resourceDid,documentDigest:attempt.candidateDigest,
      packageVersion:'1.0.0',registrarVersion:'1.0.0',source:'trusted-discovery',evidenceRef:'verified-root-package'}};},...overrides,
  };
  return {backend,keys,workflow:new DurableRegistrationWorkflow(keys,backend,approve),counts:()=>({prepares,submits}),close(){keys.lock();store.close();}};
}

test('PUB: denied prepare creates neither identity nor journal; denied publish sends no request',async()=>{
  let allowed=false;const ctx=setup({},async()=>allowed);
  try{
    await assert.rejects(ctx.workflow.prepare(owner,{identityRef:'agent',description:{}}),/publication_approval_required/);
    assert.deepEqual(ctx.counts(),{prepares:0,submits:0});
    allowed=true;const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{}});
    allowed=false;await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_approval_required/);
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'candidate');
    assert.deepEqual(ctx.counts(),{prepares:1,submits:0});
  }finally{ctx.close();}
});

test('PUB/SEC: approval is bound to original caller, identity reference and description across await',async()=>{
  const caller={...owner},input={identityRef:'agent',description:{version:'1.0.0'}};
  let prepared:any;
  const ctx=setup({async prepare(ref,description){prepared={ref,description};return {resourceDid:'did:oan:stable',candidate:prepared};}},async approvedCaller=>{
    caller.tenantId='other';input.identityRef='other';input.description.version='unapproved';approvedCaller.tenantId='mutated-callback';return true;
  });
  try{
    const draft=await ctx.workflow.prepare(caller,input);
    assert.deepEqual(prepared,{ref:'agent',description:{version:'1.0.0'}});
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).identityRef,'agent');
    await assert.rejects(ctx.workflow.inspect(caller,draft.draftId),/publication_access_denied/);
  }finally{ctx.close();}
});

test('PUB: concurrent prepare claims journal before generating identity, and changed candidate is refused',async()=>{
  let entered!:()=>void,release!:()=>void,calls=0;
  const ready=new Promise<void>(r=>entered=r),gate=new Promise<void>(r=>release=r);
  const ctx=setup({async prepare(){calls++;entered();await gate;return {resourceDid:'did:oan:stable',candidate:{}};}});
  const first=ctx.workflow.prepare(owner,{identityRef:'agent',description:{version:1}});
  try{
    await ready;
    await assert.rejects(ctx.workflow.prepare(owner,{identityRef:'agent',description:{version:1}}),/publication_preparation_incomplete/);
    release();const draft=await first;assert.equal(calls,1);
    await assert.rejects(ctx.workflow.prepare(owner,{identityRef:'agent',description:{version:2}}),/publication_candidate_conflict/);
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'candidate');
  }finally{release();await first.catch(()=>{});ctx.close();}
});

test('PUB: crashed initial preparation retains claim and never generates a second identity',async()=>{
  let calls=0;const ctx=setup({async prepare(){calls++;throw new Error('private-backend-detail');}});
  try{
    await assert.rejects(ctx.workflow.prepare(owner,{identityRef:'agent',description:{}}),{message:'publication_preparation_incomplete'});
    await assert.rejects(ctx.workflow.prepare(owner,{identityRef:'agent',description:{}}),/publication_preparation_incomplete/);
    assert.equal(calls,1);
  }finally{ctx.close();}
});

test('PUB: unknown preflight errors remain candidates and do not send or expose backend secrets',async()=>{
  const ctx=setup({async preflight(){throw new Error('private-backend-detail');}});
  try{
    const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{}});
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),{message:'publication_preflight_failed'});
    assert.equal(ctx.counts().submits,0);assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'candidate');
  }finally{ctx.close();}
});

test('PUB: known pre-acceptance rejection permits approved same-DID replacement; ambiguous failure never does',async()=>{
  const conflict=new Error('version conflict');let reject=true,calls=0;
  const ctx=setup({async submit(){calls++;if(reject)throw conflict;return {response:{} as any,materialDirectory:'private/materials'};},
    rejectedBeforeAcceptance:error=>error===conflict});
  try{
    const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{version:1}});
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_rejected_before_acceptance/);
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'rejected');
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_reconciliation_required/);
    assert.deepEqual(await ctx.workflow.prepare(owner,{identityRef:'agent',description:{version:2}}),draft);
    reject=false;await ctx.workflow.submit(owner,draft.draftId);assert.equal(calls,2);
  }finally{ctx.close();}
});

test('PUB: mismatched trusted observation cannot register accepted submission or authorize resend',async()=>{
  const ctx=setup({async reconcile(attempt){return {kind:'confirmed',evidence:{resourceDid:'different-did',documentDigest:attempt.candidateDigest,
    packageVersion:'1',registrarVersion:'1',source:'trusted',evidenceRef:'verified'}};}});
  try{
    const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{}});
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_evidence_binding_mismatch/);
    await assert.rejects(ctx.workflow.inspect(owner,draft.draftId),/publication_evidence_binding_mismatch/);
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_reconciliation_required/);
    assert.equal(ctx.counts().submits,1);
  }finally{ctx.close();}
});

test('PUB: read-only material recovery can retry after local failure without another registration',async()=>{
  let recoveries=0;
  const ctx=setup({async submit(){throw new Error('response lost');},async recoverResult(){
    if(++recoveries===1)throw new Error('temporary material write failure');return {response:{} as any,materialDirectory:'recovered'};
  }});
  try{
    const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{}});
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_reconciliation_required/);
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'registered');
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/temporary material write failure/);
    assert.equal((await ctx.workflow.submit(owner,draft.draftId)).materialDirectory,'recovered');assert.equal(recoveries,2);
  }finally{ctx.close();}
});

test('PUB: rejection classifier failure preserves uncertainty and hides backend exception',async()=>{
  let submissions=0;
  const ctx=setup({async submit(){submissions++;throw new Error('transport failure');},
    rejectedBeforeAcceptance(){throw new Error('private-classifier-secret');},async reconcile(){return {kind:'unknown'};}});
  try{
    const draft=await ctx.workflow.prepare(owner,{identityRef:'agent',description:{}});
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),{message:'publication_reconciliation_required'});
    assert.equal((await ctx.workflow.inspect(owner,draft.draftId)).state,'uncertain');
    await assert.rejects(ctx.workflow.submit(owner,draft.draftId),/publication_reconciliation_required/);
    assert.equal(submissions,1);
  }finally{ctx.close();}
});

test('PUB/SEC: caller mutation while submit reads storage cannot alter publication approval',async()=>{
  const caller={...owner};let approvedTenant='';
  const ctx=setup({},async(c,input)=>{if(input.operation==='publish')approvedTenant=c.tenantId??'';return true;});
  try{
    const draft=await ctx.workflow.prepare(caller,{identityRef:'agent',description:{}});
    const pending=ctx.workflow.submit(caller,draft.draftId);caller.tenantId='other';
    await pending;assert.equal(approvedTenant,owner.tenantId);
  }finally{ctx.close();}
});
