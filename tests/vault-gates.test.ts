// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createOanIdentityRecord,signDidDocumentProof} from '@openagenet/oan-sdk-ts';
import {EncryptedKeyProvider,LocalIdentityVault,MemoryAuditSink,digestJson} from '../src/index.js';
import type {IdentityImportBundle} from '../src/index.js';
import {SqliteBlobStore} from '../src/store/sqlite.js';
const caller={callerId:'owner',tenantId:'lab'};
async function fixture(){
  const store=new SqliteBlobStore(':memory:'),keys=new EncryptedKeyProvider(store);keys.unlock(randomBytes(32));
  let now=Date.now();const vault=new LocalIdentityVault(keys,new MemoryAuditSink(),undefined,()=>now);
  const identity=JSON.parse(JSON.stringify(await createOanIdentityRecord({label:'vault-negative',resourceType:'skill',kind:'agent'})));
  identity.didDocument=await signDidDocumentProof(identity.didDocument,identity);
  const bundle:IdentityImportBundle={identity,didDocument:identity.didDocument,sources:[]};
  return {keys,vault,bundle,now:()=>now,advance:()=>{now+=10000;},
    async lease(b=bundle){return vault.issueImportLease(caller,'agent',await digestJson(b),new Date(now+5000).toISOString());},
    close(){keys.lock();store.close();}};
}

for(const [name,mutate,code] of [
  ['unsupported source',(b:any)=>{b.sources=[{kind:'discovery',uri:'file:///private'}];},'invalid_evidence_source'],
  ['inconsistent document',(b:any)=>{b.didDocument=structuredClone(b.didDocument);b.didDocument.id='did:oan:other';},'identity_document_binding_mismatch'],
  ['invalid document signature',(b:any)=>{b.didDocument.proof.proofValue='z111';b.identity.didDocument=b.didDocument;},'document_verification_failed'],
  ['missing assertion key',(b:any)=>{b.didDocument.assertionMethod=[];b.identity.didDocument=b.didDocument;},'identity_key_binding_mismatch'],
  ['untrusted registration credential',(b:any)=>{b.registrationVc={credentialSubject:{id:b.identity.did}};},'trusted_evidence_verifier_required'],
] as const)test('LOC: '+name+' leaves no key, material or catalog record',async()=>{
  const ctx=await fixture();
  try{
    mutate(ctx.bundle);const lease=await ctx.lease();
    await assert.rejects(ctx.vault.importIdentity(caller,ctx.bundle,lease),new RegExp(code));
    assert.deepEqual(await ctx.vault.list(),[]);
    assert.equal(await ctx.keys.readRecord('host:key:agent'),undefined);
    assert.equal(await ctx.keys.readRecord('host:material:agent'),undefined);
    await assert.rejects(ctx.vault.importIdentity(caller,ctx.bundle,lease),/capability_lease_denied/);
  }finally{ctx.close();}
});

test('LOC: lease digest rejects changed import and consumes the lease',async()=>{
  const ctx=await fixture();
  try{
    const lease=await ctx.lease(),original=structuredClone(ctx.bundle);ctx.bundle.sources=[{kind:'discovery',uri:'https://different.example'}];
    await assert.rejects(ctx.vault.importIdentity(caller,ctx.bundle,lease),/import_candidate_mismatch/);
    await assert.rejects(ctx.vault.importIdentity(caller,original,lease),/capability_lease_denied/);
    assert.deepEqual(await ctx.vault.list(),[]);
  }finally{ctx.close();}
});

test('LOC: lease expiring during evidence verification fails before atomic material commit',async()=>{
  const ctx=await fixture();
  try{
    const vault=new LocalIdentityVault(ctx.keys,new MemoryAuditSink(),{rootDid:'root',verifier:{async verifyRegistration(){
      ctx.advance();return {valid:true,checks:[{name:'privateVc',status:'passed'}]};
    }}},ctx.now);
    ctx.bundle.registrationVc={};const lease=vault.issueImportLease(caller,'agent',await digestJson(ctx.bundle),new Date(ctx.now()+5000).toISOString());
    await assert.rejects(vault.importIdentity(caller,ctx.bundle,lease),/capability_lease_denied/);
    assert.deepEqual(await vault.list(),[]);assert.equal(await ctx.keys.readRecord('host:key:agent'),undefined);
  }finally{ctx.close();}
});

test('LOC: secondary audit failure cannot turn committed import into failure',async()=>{
  const ctx=await fixture();
  try{
    const vault=new LocalIdentityVault(ctx.keys,{async append(){throw new Error('unavailable');}});
    const lease=vault.issueImportLease(caller,'agent',await digestJson(ctx.bundle),new Date(Date.now()+5000).toISOString());
    assert.equal((await vault.importIdentity(caller,ctx.bundle,lease)).status,'local_ready');
    assert.equal((await vault.list()).length,1);assert(await ctx.keys.readRecord('host:material:agent'));
  }finally{ctx.close();}
});
