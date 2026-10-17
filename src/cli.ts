#!/usr/bin/env node
// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

import { FRAMEWORK_CAPABILITIES } from './tools/index.js';
const command = process.argv[2] ?? 'help';
if (command === 'capabilities') console.log(JSON.stringify(FRAMEWORK_CAPABILITIES, null, 2));
else if (command === 'help' || command === '--help') console.log('Usage: oan-identity-runtime capabilities');
else { console.error('unsupported_command'); process.exitCode = 2; }
