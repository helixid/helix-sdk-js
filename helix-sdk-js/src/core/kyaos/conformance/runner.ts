// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The conformance runner (KYA-OS story F-2): loads the vendored vector files
 * (helix-core fixtures/kya-os/conformance/vectors), feeds each vector to a
 * {@link ConformanceAdapter} and compares the adapter's accept or reject with
 * the vector's `expected`, as upstream's `conformance/runner.ts` does. A
 * thrown error is a harness failure, never a rejection.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { AdapterResult, ConformanceAdapter, ConformanceVector, VectorCategory, VectorFile } from './types.js';

export interface VectorRunResult {
  id: string;
  category: VectorCategory;
  expected: 'pass' | 'fail';
  actual: 'pass' | 'fail' | 'error';
  ok: boolean;
  detail?: string | undefined;
}

export interface ConformanceReport {
  adapter: string;
  total: number;
  passed: number;
  failed: number;
  results: VectorRunResult[];
  allMatched: boolean;
  /** Totals by category. */
  categories: Record<string, { total: number; passed: number }>;
}

/** Every vector of every file in `vectorsDir`, or of the named categories only. */
export function loadVectors(vectorsDir: string, categories?: readonly VectorCategory[]): ConformanceVector[] {
  const vectors: ConformanceVector[] = [];
  const seen = new Set<string>();
  for (const name of readdirSync(vectorsDir).filter((entry) => entry.endsWith('.json')).sort()) {
    const file = JSON.parse(readFileSync(join(vectorsDir, name), 'utf8')) as VectorFile;
    if (categories !== undefined && !categories.includes(file.category)) continue;
    for (const vector of file.vectors) {
      if (seen.has(vector.id)) throw new Error(`duplicate vector id ${vector.id} in ${name}`);
      seen.add(vector.id);
      vectors.push(vector);
    }
  }
  return vectors;
}

function dispatch(adapter: ConformanceAdapter, vector: ConformanceVector): Promise<AdapterResult> {
  const input = vector.input as never;
  switch (vector.category) {
    case 'signed-proof':
      return adapter.verifySignedProof(input);
    case 'delegation-chain':
      return adapter.verifyDelegationChain(input);
    case 'status-list':
      return adapter.verifyStatusList(input);
    case 'did-key-resolution':
      return adapter.resolveDidKey(input);
    case 'did-web-resolution':
      return adapter.resolveDidWeb(input);
    case 'card-proof':
      return adapter.verifyCardProof(input);
    case 'entity-card':
      return adapter.verifyEntityCard(input);
    case 'audit-integrity':
      return adapter.verifyAuditIntegrity(input);
    case 'negotiation':
      return adapter.evaluateNegotiation(input);
    default:
      return Promise.reject(new Error(`unknown vector category ${String(vector.category)}`));
  }
}

export async function runConformance(adapter: ConformanceAdapter, vectors: readonly ConformanceVector[]): Promise<ConformanceReport> {
  const results: VectorRunResult[] = [];
  for (const vector of vectors) {
    let actual: VectorRunResult['actual'];
    let detail: string | undefined;
    try {
      const result = await dispatch(adapter, vector);
      actual = result.outcome;
      detail = result.detail;
    } catch (error) {
      actual = 'error';
      detail = `adapter threw: ${error instanceof Error ? error.message : String(error)}`;
    }
    results.push({ id: vector.id, category: vector.category, expected: vector.expected, actual, ok: actual === vector.expected, detail });
  }
  const categories: ConformanceReport['categories'] = {};
  for (const result of results) {
    const entry = (categories[result.category] ??= { total: 0, passed: 0 });
    entry.total += 1;
    if (result.ok) entry.passed += 1;
  }
  const passed = results.filter((result) => result.ok).length;
  return { adapter: adapter.name, total: results.length, passed, failed: results.length - passed, results, allMatched: passed === results.length, categories };
}

export function formatReport(report: ConformanceReport): string {
  const lines = [`KYA-OS conformance, adapter: ${report.adapter}`, ''];
  for (const result of report.results) {
    lines.push(`  [${result.ok ? 'PASS' : 'FAIL'}] ${result.id} (${result.category}): expected ${result.expected}, got ${result.actual}`);
    if (!result.ok && result.detail) lines.push(`         ${result.detail}`);
  }
  lines.push('');
  for (const [category, totals] of Object.entries(report.categories)) lines.push(`  ${category}: ${totals.passed}/${totals.total}`);
  lines.push(`Total: ${report.total}  Passed: ${report.passed}  Failed: ${report.failed}`);
  lines.push(report.allMatched ? 'RESULT: PASS (all vectors matched)' : 'RESULT: FAIL');
  return lines.join('\n');
}
