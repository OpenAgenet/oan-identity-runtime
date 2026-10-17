// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOanIdentityRecord,signDidDocumentProof} from '@openagenet/oan-sdk-ts';
import {EncryptedAuditSink,EncryptedKeyProvider,LocalIdentityVault,MemoryAuditSink,digestJson,DurableRegistrationWorkflow,RuntimeToolHost,ResourceDirectory,RuntimeError} from '../src/index.js';
import type {PublicationBackend,IdentityImportBundle} from '../src/index.js';
import {SqliteBlobStore} from '../src/store/sqlite.js';
const caller={callerId:'trusted-host',tenantId:'tenant-a'};

test('leased import validates actual keys, persists encrypted material, and invalidates cached signers',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'oan-vault-')),file=join(dir,'vault.sqlite'),master=randomBytes(32);
  let store=new SqliteBlobStore(file),now=Date.now();
  const keys=new EncryptedKeyProvider(store,()=>now);keys.unlock(master,now+60000);
  const audit=new MemoryAuditSink(),vault=new LocalIdentityVault(keys,audit,undefined,()=>now);
  const identity=JSON.parse(JSON.stringify(await createOanIdentityRecord({label:'vault-import',resourceType:'skill',kind:'agent'})));
  identity.didDocument=await signDidDocumentProof(identity.didDocument,identity);
  const bundle:IdentityImportBundle={identity,didDocument:identity.didDocument,sources:[]};
  const lease=async(ref:string,b=bundle,c=caller)=>vault.issueImportLease(c,ref,await digestJson(b),new Date(now+10000).toISOString());
  try{
    const denied=await lease('denied');
    await assert.rejects(vault.importIdentity({...caller,tenantId:'other'},bundle,denied),/capability_lease_denied/);
    await assert.rejects(vault.importIdentity(caller,bundle,denied),/capability_lease_denied/);
    const bad=structuredClone(bundle);bad.identity.privateKeyJwk=JSON.parse(JSON.stringify((await createOanIdentityRecord({label:'other',resourceType:'skill',kind:'agent'})).privateKeyJwk));
    await assert.rejects(vault.importIdentity(caller,bad,await lease('bad',bad)),/identity_key_binding_mismatch/);
    const expired=await lease('expired');now+=11000;
    await assert.rejects(vault.importIdentity(caller,bundle,expired),/capability_lease_denied/);
    const publicRecord=await vault.importIdentity(caller,bundle,await lease('resource'));
    assert.equal(publicRecord.status,'local_ready');
    assert.equal(JSON.stringify(publicRecord).includes('keyRef'),false);
    const signer=await keys.getSigner('host:key:resource');
    assert.equal((await signer.signPreparedInput(new Uint8Array([1]))).length,64);
    keys.lock();await assert.rejects(signer.signPreparedInput(new Uint8Array([1])),/vault_locked/);
    keys.unlock(master,now+1000);await assert.rejects(signer.publicKey(),/vault_locked/);
    const fresh=await keys.getSigner('host:key:resource');now+=1001;
    await assert.rejects(fresh.signPreparedInput(new Uint8Array([1])),/vault_locked/);
    store.close();
    assert.equal((await readFile(file)).includes(Buffer.from(identity.privateKeyJwk.d as string)),false);
    store=new SqliteBlobStore(file);const restored=new EncryptedKeyProvider(store);restored.unlock(master);
    const restoredVault=new LocalIdentityVault(restored,audit);
    assert.equal((await restoredVault.get('resource')).did,identity.did);
    assert.equal((await restored.getSigner('host:key:resource')).keyId,identity.verificationMethodId);
    restored.lock();
  }finally{store.close();await rm(dir,{recursive:true,force:true});}
});

test('publication journal retains DID across restart, timeout and failed update; never blindly resubmits',async()=>{
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store);keys.unlock(randomBytes(32));
  let preparations=0,submissions=0,timeout=true,wrongDid=false;
  const did='did:oan:K7mQ9:22222222222222222222222222222222';
  const backend:PublicationBackend={
    async prepare(_ref,description){preparations++;return {resourceDid:wrongDid?'wrong':did,candidate:{description}};},
    async submit(){submissions++;if(timeout)throw new Error('timeout');return {response:{} as any,materialDirectory:'host-only'};},
    async reconcile(a){return {kind:'confirmed',evidence:{resourceDid:did,documentDigest:a.candidateDigest,packageVersion:'1.0.0',registrarVersion:'1.0.0',source:'fixture',evidenceRef:'root-verified'}};},
    async recoverResult(){return {response:{} as any,materialDirectory:'recovered-read-only'};},
  };
  const make=()=>new DurableRegistrationWorkflow(keys,backend,async()=>true);
  try{
    let workflow=make();const draft=await workflow.prepare(caller,{identityRef:'resource',description:{version:1}});
    assert.deepEqual(await workflow.prepare(caller,{identityRef:'resource',description:{version:1}}),draft);assert.equal(preparations,1);
    await assert.rejects(workflow.submit(caller,draft.draftId),/publication_reconciliation_required/);
    workflow=make();await assert.rejects(workflow.submit(caller,draft.draftId),/publication_reconciliation_required/);
    assert.equal(submissions,1);assert.equal((await workflow.inspect(caller,draft.draftId)).state,'registered');
    assert.equal((await workflow.submit(caller,draft.draftId)).materialDirectory,'recovered-read-only');
    assert.equal(submissions,1);
    await assert.rejects(workflow.inspect({...caller,tenantId:'other'},draft.draftId),/publication_access_denied/);
    wrongDid=true;await assert.rejects(workflow.prepare(caller,{identityRef:'resource',description:{version:2}}),/publication_candidate_invalid/);
    assert.equal((await workflow.inspect(caller,draft.draftId)).resourceDid,did);
    assert.equal((await workflow.inspect(caller,draft.draftId)).state,'registered');
    wrongDid=false;timeout=false;
    await workflow.prepare(caller,{identityRef:'resource',description:{version:2}});
    const results=await Promise.allSettled([workflow.submit(caller,draft.draftId),workflow.submit(caller,draft.draftId)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(submissions,2);
    assert.equal((await workflow.inspect(caller,draft.draftId)).state,'registered');
  }finally{keys.lock();store.close();}
});

test('tool host exposes installed handlers only and refuses identity/trust/caller injection',async()=>{
  const host=new RuntimeToolHost({caller,directory:new ResourceDirectory()});
  assert.deepEqual(host.list().map(t=>t.name),['resource.discover','resource.resolve']);
  for(const args of [{callerId:'evil'},{query:{tenantId:'evil'}},{query:{privateKeyJwk:{d:'secret'}}},{query:{trustAnchor:{}}}]){
    await assert.rejects(host.call('resource.discover',args),RuntimeError);
  }
  await assert.rejects(host.call('resource.discover',{query:{text:'x'.repeat(1_000_001)}}),/invalid_tool_arguments/);
  const cycle:any={};cycle.self=cycle;
  await assert.rejects(host.call('resource.discover',{query:cycle}),/invalid_tool_arguments/);
  await assert.rejects(host.call('identity.import',{}),/unsupported_tool/);
  await assert.rejects(host.call('resource.resolve',{resourceDid:12}),/invalid_tool_arguments/);
});

test('tool publication output contains a material location, never private VC or response extras',async()=>{
  const host=new RuntimeToolHost({caller,directory:new ResourceDirectory(),registration:{
    async prepare(){return {draftId:'draft',resourceDid:'resource'};},async inspect(){return {};},
    async submit(){return {resourceDid:'resource',materialDirectory:'host-only-path',response:{status:'submitted',registrationCredential:{secret:'never-return'},privateKeyJwk:{d:'never-return'}} as any};},
  }});
  assert.deepEqual(await host.call('resource.register',{action:'submit',draftId:'draft'}),{resourceDid:'resource',materialDirectory:'host-only-path',status:'submitted'});
});

test('encrypted audit sink persists only allowlisted event fields',async()=>{
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store);keys.unlock(randomBytes(32));
  let recordId='';
  const commit=keys.commitRecords.bind(keys);
  keys.commitRecords=async records=>{recordId=records[0].id;return commit(records);};
  try{
    await new EncryptedAuditSink(keys).append({timestamp:'2026-10-17T00:00:00.000Z',action:'resource.resolve',outcome:'allowed',identityRef:'did:oan:test',code:'ok'});
    const row=await keys.readRecord<Record<string,unknown>>(recordId);
    assert.deepEqual(row?.value,{timestamp:'2026-10-17T00:00:00.000Z',action:'resource.resolve',outcome:'allowed',identityRef:'did:oan:test',code:'ok'});
    assert.equal(JSON.stringify(row?.value).includes('payload'),false);
  }finally{keys.lock();store.close();}
});

test('publication preflight refreshes expired unsent proofs with approval and retains the same DID',async()=>{
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store);keys.unlock(randomBytes(32));
  let expired=false,prepares=0,submits=0,approvals=0;
  const backend:PublicationBackend={
    async prepare(){prepares++;expired=false;return {resourceDid:'same-did',candidate:{revision:prepares}};},
    async preflight(){if(expired)throw new Error('registration_proof_expired_before_submission');},
    async submit(){submits++;return {response:{} as any,materialDirectory:'local'};},
    async reconcile(){return {kind:'unknown'};},
  };
  const workflow=new DurableRegistrationWorkflow(keys,backend,async()=>{approvals++;return true;});
  try{
    const draft=await workflow.prepare(caller,{identityRef:'resource',description:{}});expired=true;
    await assert.rejects(workflow.submit(caller,draft.draftId),/registration_proof_expired/);
    assert.equal(submits,0);assert.equal((await workflow.inspect(caller,draft.draftId)).state,'candidate');
    assert.deepEqual(await workflow.prepare(caller,{identityRef:'resource',description:{}}),draft);
    assert.equal(prepares,2);assert.equal(approvals,3);
    await assert.rejects(workflow.submit(caller,draft.draftId),/reconciliation_required/);
    expired=true;await workflow.prepare(caller,{identityRef:'resource',description:{}});
    assert.equal(prepares,2);assert.equal(submits,1);
  }finally{keys.lock();store.close();}
});

test('concurrent imports commit only one catalog/key/material set and wrong master key fails closed',async()=>{
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store),master=randomBytes(32);keys.unlock(master);
  const vault=new LocalIdentityVault(keys,new MemoryAuditSink());
  const identity=JSON.parse(JSON.stringify(await createOanIdentityRecord({label:'concurrent-import',resourceType:'skill',kind:'agent'})));
  identity.didDocument=await signDidDocumentProof(identity.didDocument,identity);
  const bundle:IdentityImportBundle={identity,didDocument:identity.didDocument,sources:[]};
  const lease=()=>vault.issueImportLease(caller,'resource',digest,new Date(Date.now()+60000).toISOString());
  const digest=await digestJson(bundle);
  try{
    const results=await Promise.allSettled([vault.importIdentity(caller,bundle,lease()),vault.importIdentity(caller,bundle,lease())]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal((await vault.list()).length,1);
    keys.lock();keys.unlock(randomBytes(32));await assert.rejects(vault.list(),/encrypted_blob_authentication_failed/);
    keys.lock();keys.unlock(master);assert.equal((await vault.list())[0].did,identity.did);
  }finally{keys.lock();store.close();}
});
