// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import type {CallerContext} from '../policy/index.js';
import {SynchronousInvocation,attachOanMetadata,detachOanMetadata} from './synchronous.js';
import {RuntimeError} from '../errors.js';

/** Install at the actual SDK handler boundary. Other native auth remains upstream.
 * Codec MUST be the same pinned SDK conversion on both ends (including defaults).
 * A2A streaming/task retrieval require separate profiles and are denied by this API.
 */
export class NativeSynchronousBoundary {
  private readonly caller:CallerContext;
  constructor(private readonly endpoint:SynchronousInvocation,caller:CallerContext,
    private readonly metadataField:'_meta'|'metadata',
    private readonly codec:(value:Record<string,unknown>)=>Record<string,unknown> = value=>value,
    private readonly resultCodec:(value:Record<string,unknown>)=>Record<string,unknown> = codec){this.caller=structuredClone(caller);}
  private normalize(value:Record<string,unknown>,response=false){
    const object=(response?this.resultCodec:this.codec)(structuredClone(value)),meta=object[this.metadataField];
    // Native SDKs may materialize an empty metadata map. Absence and an empty map
    // have the same native meaning; normalize only this top-level carrier field.
    if(meta && typeof meta==='object' && !Array.isArray(meta) && !Object.keys(meta).length)delete object[this.metadataField];
    return object;
  }
  async handle(input:Record<string,unknown>,handler:(actual:Record<string,unknown>)=>Promise<Record<string,unknown>>){
    const {object,message}=detachOanMetadata(this.normalize(input),this.metadataField);
    const exchange=await this.endpoint.receive(this.caller,message,object,async actual=>this.normalize(await handler(actual as Record<string,unknown>),true));
    return attachOanMetadata(exchange.result as Record<string,unknown>,this.metadataField,exchange.message);
  }
  async call(sessionRef:string,requestId:string,input:Record<string,unknown>,dispatch:(actual:Record<string,unknown>)=>Promise<Record<string,unknown>>){
    const actual=this.normalize(input);
    const verified=await this.endpoint.execute(this.caller,{sessionRef,requestId,payload:actual},async(message,object)=>{
      const response=await dispatch(attachOanMetadata(object as Record<string,unknown>,this.metadataField,message));
      const decoded=detachOanMetadata(this.normalize(response,true),this.metadataField);
      return {result:decoded.object,message:decoded.message};
    });
    return verified.result as Record<string,unknown>;
  }
}

/** HTTP application envelope: bind exact method, raw target, selected headers and bytes.
 * Host owns the header allowlist; TLS/auth/redirect policy stays in its HTTP transport.
 */
export function httpRequestObject(input:{method:string;target:string;headers:Array<[string,string]>;body:Uint8Array}){
  if(!/^[A-Z]+$/.test(input.method) || !input.target.startsWith('/') || /[\r\n]/.test(input.target))throw new RuntimeError('invalid_http_object');
  return {method:input.method,target:input.target,headers:structuredClone(input.headers),bodyBase64:Buffer.from(input.body).toString('base64')};
}
