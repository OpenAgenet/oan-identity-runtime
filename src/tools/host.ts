// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import type { CallerContext } from '../policy/index.js';
import type { ResourceDirectory, RegistrationWorkflow } from '../directory/index.js';
import type { IdentityRuntime } from '../runtime.js';
import type { EvidenceVerifier } from '../evidence/index.js';
import { RuntimeError } from '../errors.js';

export interface ToolDefinition { name:string; description:string; inputSchema:{type:'object';properties:Record<string,unknown>;required?:string[];additionalProperties:false} }
export interface ToolHostOptions {
  /** Authenticated startup/transport context, never taken from tool JSON. */
  caller:CallerContext;
  directory:ResourceDirectory;
  runtime?:IdentityRuntime;
  evidence?:{verifier:EvidenceVerifier;rootDid:string};
  registration?:RegistrationWorkflow & {inspect(caller:CallerContext,draftId:string):Promise<unknown>};
}
const definition=(name:string,description:string,properties:Record<string,unknown>,required:string[]=[]):ToolDefinition=>
  ({name,description,inputSchema:{type:'object',properties,required,additionalProperties:false}});
const text={type:'string',minLength:1};
/** Installed L0/L1 handlers only. No import, unlock, export, arbitrary sign or pretend G3 tools. */
export class RuntimeToolHost {
  private readonly caller:CallerContext;
  constructor(private readonly options:ToolHostOptions){
    if(!options.caller.callerId)throw new RuntimeError('host_authentication_required');
    this.caller=structuredClone(options.caller);
  }
  list():ToolDefinition[]{
    const tools=[definition('resource.discover','Discover public resources through host-configured OAN services.',{query:{type:'object'}}),
      definition('resource.resolve','Resolve a public OAN resource. Does not establish L1 trust.',{resourceDid:text},['resourceDid'])];
    if(this.options.runtime)tools.push(definition('identity.list','List identities permitted for this authenticated host.',{}),
      definition('identity.select','Select one permitted identity explicitly; no global active identity.',{identityRef:text},['identityRef']));
    if(this.options.evidence)tools.push(definition('evidence.inspect','Verify public document/package against the HOST pinned Root. No private credentials accepted.',
      {expectedResourceDid:text,didDocument:{type:'object'},resourcePackage:{type:'object'}},['expectedResourceDid','didDocument']));
    if(this.options.registration)tools.push(definition('resource.register','Prepare a stable candidate, then submit only with host approval. Never pass key paths.',
      {action:{type:'string',enum:['prepare','submit']},identityRef:text,description:{type:'object'},draftId:text},['action']),
      definition('publication.inspect','Inspect/reconcile an existing publication without creating an identity.',{draftId:text},['draftId']));
    return tools;
  }
  async call(name:string,input:unknown):Promise<unknown>{
    const tool=this.list().find(t=>t.name===name);
    if(!tool)throw new RuntimeError('unsupported_tool');
    if(!input || typeof input!=='object' || Array.isArray(input))throw new RuntimeError('invalid_tool_arguments');
    const args=structuredClone(input) as Record<string,any>;
    for(const field of Object.keys(args))if(!Object.hasOwn(tool.inputSchema.properties,field))throw new RuntimeError('invalid_tool_arguments');
    for(const field of tool.inputSchema.required??[])if(args[field]===undefined)throw new RuntimeError('invalid_tool_arguments');
    for(const [field,schema] of Object.entries(tool.inputSchema.properties)){
      if(args[field]===undefined)continue;
      const s=schema as {type:string;enum?:string[]};
      if(typeof args[field]!==s.type || (s.type==='object' && (!args[field] || Array.isArray(args[field])))
        || (s.type==='string' && !args[field]) || (s.enum && !s.enum.includes(args[field])))throw new RuntimeError('invalid_tool_arguments');
    }
    rejectSecrets(args);
    const caller=structuredClone(this.caller);
    switch(name){
      case 'resource.discover':return this.options.directory.discover(args.query??{});
      case 'resource.resolve':return this.options.directory.resolve(args.resourceDid);
      case 'identity.list':return this.options.runtime!.listIdentities(caller);
      case 'identity.select':{
        const identity=(await this.options.runtime!.listIdentities(caller)).find(i=>i.id===args.identityRef);
        if(!identity)throw new RuntimeError('identity_access_denied');return identity;
      }
      case 'evidence.inspect':return this.options.evidence!.verifier.verifyRegistration({...args,
        trustAnchor:{mode:'pinned-root',rootDid:this.options.evidence!.rootDid}} as Parameters<EvidenceVerifier['verifyRegistration']>[0]);
      case 'resource.register':
        if(args.action==='prepare'){
          if(!args.identityRef || !args.description || args.draftId)throw new RuntimeError('invalid_tool_arguments');
          return this.options.registration!.prepare(caller,{identityRef:args.identityRef,description:args.description});
        }
        if(!args.draftId || args.description || args.identityRef)throw new RuntimeError('invalid_tool_arguments');
        return this.options.registration!.submit(caller,args.draftId);
      case 'publication.inspect':return this.options.registration!.inspect(caller,args.draftId);
    }
  }
}
function rejectSecrets(value:unknown):void{
  if(!value || typeof value!=='object')return;
  for(const [key,entry] of Object.entries(value)){
    if(/^(privateKey.*|d|identityDir|identityPath|subjectIdentityPath|controllerIdentityPath|agentIdentityPath|callerId|tenantId|trustAnchor|keyRef)$/i.test(key))throw new RuntimeError('host_only_argument');
    rejectSecrets(entry);
  }
}
