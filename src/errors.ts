// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

export class RuntimeError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'RuntimeError'; }
}
export function unsupported(feature: string): never { throw new RuntimeError(`unsupported:${feature}`); }
