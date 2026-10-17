#!/usr/bin/env node
// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { RuntimeToolHost } from './tools/host.js';
import { ResourceDirectory } from './directory/index.js';
import { serveMcp } from './tools/mcp.js';
import { RuntimeError } from './errors.js';

try {
  const [command = 'help', ...args] = process.argv.slice(2);
  if (command === 'help' || command === '--help') {
    console.log('Usage: oan-identity-runtime <capabilities|call|mcp> [--host trusted-host.mjs] [--tool name --input input.json]\nThe optional host module is trusted local startup configuration exporting createToolHost(). Default: public discovery/query only.');
  } else {
    if (!['capabilities','call','mcp'].includes(command)) throw new RuntimeError('unsupported_command');
    const flags: Record<string,string> = {};
    for (let i=0;i<args.length;i+=2) {
      const key=args[i], value=args[i+1];
      if (!['--host', ...(command==='call'?['--tool','--input']:[])].includes(key) || !value || value.startsWith('--') || flags[key]) throw new RuntimeError('invalid_cli_arguments');
      flags[key]=value;
    }
    const host = flags['--host']
      ? await (await import(pathToFileURL(resolve(flags['--host'])).href)).createToolHost()
      : new RuntimeToolHost({caller:{callerId:'local-cli'},directory:new ResourceDirectory()});
    if (!(host instanceof RuntimeToolHost)) throw new RuntimeError('invalid_host_configuration');
    if (command==='capabilities') console.log(JSON.stringify({version:1,tools:host.list()},null,2));
    else if (command==='mcp') await serveMcp(host);
    else {
      if (!flags['--tool'] || !flags['--input']) throw new RuntimeError('invalid_cli_arguments');
      console.log(JSON.stringify(await host.call(flags['--tool'],JSON.parse(await readFile(resolve(flags['--input']),'utf8'))),null,2));
    }
  }
} catch (error) {
  console.error(JSON.stringify({ok:false,errorCode:error instanceof RuntimeError?error.code:'host_execution_failed'}));
  process.exitCode=1;
}
