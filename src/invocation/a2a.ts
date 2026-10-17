// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import {SendMessageRequest,Task,Message,type SendMessageResult} from '@a2a-js/sdk';
import type {A2ARequestHandler} from '@a2a-js/sdk/server';
import type {CallerContext} from '../policy/index.js';
import type {SynchronousInvocation} from './synchronous.js';
import {NativeSynchronousBoundary} from './native.js';
import {RuntimeError} from '../errors.js';
export const a2aRequestObject=(value:Record<string,unknown>)=>SendMessageRequest.toJSON(SendMessageRequest.fromJSON(value)) as Record<string,unknown>;
export const a2aResultObject=(value:Record<string,unknown>)=>(Object.hasOwn(value,'messageId')?Message.toJSON(Message.fromJSON(value)):Task.toJSON(Task.fromJSON(value))) as Record<string,unknown>;
export const createA2aBoundary=(endpoint:SynchronousInvocation,caller:CallerContext)=>new NativeSynchronousBoundary(endpoint,caller,'metadata',a2aRequestObject,a2aResultObject);
/** Pinned A2A SDK 1.3.0/protocol 1.0 synchronous handler. No bare task/stream fallback. */
export function protectA2aHandler(handler:A2ARequestHandler,boundary:NativeSynchronousBoundary):A2ARequestHandler{
  return new Proxy(handler,{get(target,key){
    if(key==='sendMessage')return async(request:SendMessageRequest,context:Parameters<A2ARequestHandler['sendMessage']>[1])=>{
      if(request.configuration?.returnImmediately || request.configuration?.taskPushNotificationConfig)throw new RuntimeError('protected_async_operation_unsupported');
      const result=await boundary.handle(SendMessageRequest.toJSON(request) as Record<string,unknown>,async actual=>{
        const native=await target.sendMessage(SendMessageRequest.fromJSON(actual),context);
        return ('messageId' in native?Message.toJSON(native):Task.toJSON(native)) as Record<string,unknown>;
      });
      return Object.hasOwn(result,'messageId')?Message.fromJSON(result):Task.fromJSON(result);
    };
    if(key==='getAgentCard')return Reflect.get(target,key).bind(target);
    return ()=>{throw new RuntimeError('protected_operation_unsupported');};
  }});
}
/** Converts through the official SDK on both ends and preserves Message or Task results. */
export async function callA2a(boundary:NativeSynchronousBoundary,sessionRef:string,requestId:string,request:SendMessageRequest,
  dispatch:(request:SendMessageRequest)=>Promise<SendMessageResult>):Promise<SendMessageResult>{
  const result=await boundary.call(sessionRef,requestId,SendMessageRequest.toJSON(request) as Record<string,unknown>,async actual=>{
    const native=await dispatch(SendMessageRequest.fromJSON(actual));return ('messageId' in native?Message.toJSON(native):Task.toJSON(native)) as Record<string,unknown>;
  });
  return Object.hasOwn(result,'messageId')?Message.fromJSON(result):Task.fromJSON(result);
}
