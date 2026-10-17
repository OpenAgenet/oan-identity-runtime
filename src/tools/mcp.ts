// Copyright (c) 2026 OpenAgenet contributors
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { RuntimeToolHost } from './host.js';
import { RuntimeError } from '../errors.js';
export async function serveMcp(host:RuntimeToolHost){
  const server=new Server({name:'oan-identity-runtime',version:'0.1.0'},{capabilities:{tools:{}}});
  server.setRequestHandler(ListToolsRequestSchema,async()=>({tools:host.list()}));
  server.setRequestHandler(CallToolRequestSchema,async request=>{
    try{
      const data=await host.call(request.params.name,request.params.arguments??{});
      return {content:[{type:'text',text:JSON.stringify(data)}],structuredContent:{data}};
    }catch(error){
      const code=error instanceof RuntimeError?error.code:'tool_execution_failed';
      return {isError:true,content:[{type:'text',text:JSON.stringify({ok:false,errorCode:code})}]};
    }
  });
  await server.connect(new StdioServerTransport());return server;
}
