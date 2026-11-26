// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

/**
 * KYA-OS story L3-D: the delegation graph, conformance L3.14 to L3.19
 * (the reference suite's `delegation-graph.test.ts` cases, by name).
 */

import { describe, expect, it } from 'vitest';
import { DelegationGraph, createDelegationGraph, nodeOfHop, type DelegationNode } from '../src/delegation/graph.js';

const node = (id: string, issuerDid: string, subjectDid: string, parentId?: string): DelegationNode => ({ id, issuerDid, subjectDid, ...(parentId === undefined ? {} : { parentId }) });

/** root (rp → user) → a (user → agentA) → { b (agentA → agentB) → d (agentB → agentD), c (agentA → agentC) } */
function tree(): DelegationGraph {
  const graph = createDelegationGraph();
  graph.registerDelegation(node('root', 'did:rp', 'did:user'));
  graph.registerDelegation(node('a', 'did:user', 'did:agentA', 'root'));
  graph.registerDelegation(node('b', 'did:agentA', 'did:agentB', 'a'));
  graph.registerDelegation(node('c', 'did:agentA', 'did:agentC', 'a'));
  graph.registerDelegation(node('d', 'did:agentB', 'did:agentD', 'b'));
  return graph;
}

describe('DelegationGraph', () => {
  describe('registerDelegation', () => {
    it('should register a root delegation (no parent) (L3.14)', () => {
      const graph = new DelegationGraph();
      const stored = graph.registerDelegation(node('root', 'did:rp', 'did:user'));
      expect(stored).toMatchObject({ id: 'root', children: [] });
      expect(graph.getNode('root')?.parentId).toBeUndefined();
      expect(graph.size).toBe(1);
    });

    it('should register a child delegation and link to parent (L3.15)', () => {
      const graph = tree();
      expect(graph.getNode('a')?.parentId).toBe('root');
      expect(graph.getNode('root')?.children).toEqual(['a']);
      expect(graph.getChildren('a').map((child) => child.id)).toEqual(['b', 'c']);
    });

    it('should include credentialStatusId if provided', () => {
      const graph = new DelegationGraph();
      graph.registerDelegation({ ...node('root', 'did:rp', 'did:user'), credentialStatusId: 'https://l/1#4' });
      expect(graph.getNode('root')?.credentialStatusId).toBe('https://l/1#4');
    });

    it('treats an identical registration as a no-op that keeps children, and rejects a conflicting one', () => {
      const graph = tree();
      graph.registerDelegation(node('a', 'did:user', 'did:agentA', 'root'));
      expect(graph.getNode('a')?.children).toEqual(['b', 'c']);
      expect(() => graph.registerDelegation(node('a', 'did:user', 'did:other', 'root'))).toThrow(/subjectDid/);
      expect(graph.getNode('a')?.subjectDid).toBe('did:agentA');
    });

    it('rejects a delegation as its own parent, an unknown parent, and does not add duplicate children', () => {
      const graph = tree();
      expect(() => graph.registerDelegation(node('x', 'did:a', 'did:b', 'x'))).toThrow(/own parent/);
      expect(() => graph.registerDelegation(node('y', 'did:a', 'did:b', 'missing'))).toThrow(/not registered/);
      graph.registerDelegation(node('c', 'did:agentA', 'did:agentC', 'a'));
      expect(graph.getNode('a')?.children).toEqual(['b', 'c']);
    });
  });

  describe('getChildren / getDescendants', () => {
    it('should return empty array for node with no children', () => {
      expect(tree().getChildren('d')).toEqual([]);
      expect(tree().getChildren('missing')).toEqual([]);
    });

    it('should return all descendants recursively (L3.19)', () => {
      expect(tree().getDescendants('a').map((n) => n.id)).toEqual(['b', 'd', 'c']);
      expect(tree().getDescendants('root').map((n) => n.id).sort()).toEqual(['a', 'b', 'c', 'd']);
    });

    it('should return empty array for node with no descendants', () => {
      expect(tree().getDescendants('d')).toEqual([]);
    });
  });

  describe('getChain', () => {
    it('should return chain from root to node (L3.18)', () => {
      expect(tree().getChain('d').map((n) => n.id)).toEqual(['root', 'a', 'b', 'd']);
    });

    it('should return single node for root, and nothing for an unknown id', () => {
      expect(tree().getChain('root').map((n) => n.id)).toEqual(['root']);
      expect(tree().getChain('missing')).toEqual([]);
    });
  });

  describe('isAncestor / getDepth', () => {
    it('answers for parent, grandparent, a stranger and reversed nodes', () => {
      const graph = tree();
      expect(graph.isAncestor('a', 'b')).toBe(true);
      expect(graph.isAncestor('root', 'd')).toBe(true);
      expect(graph.isAncestor('c', 'd')).toBe(false);
      expect(graph.isAncestor('d', 'root')).toBe(false);
      expect(graph.isAncestor('d', 'd')).toBe(false);
    });

    it('should return 0 for root, 1 for an immediate child, the depth of nested nodes, -1 when unknown', () => {
      const graph = tree();
      expect(graph.getDepth('root')).toBe(0);
      expect(graph.getDepth('a')).toBe(1);
      expect(graph.getDepth('d')).toBe(3);
      expect(graph.getDepth('missing')).toBe(-1);
    });
  });

  describe('validateChain', () => {
    it('should validate correct chain (L3.16)', () => {
      expect(tree().validateChain('d')).toEqual({ valid: true });
    });

    it('should invalidate chain with mismatched issuer/subject (L3.17)', () => {
      const graph = tree();
      graph.registerDelegation(node('bad', 'did:mallory', 'did:agentE', 'b'));
      const result = graph.validateChain('bad');
      expect(result.valid).toBe(false);
      expect((result as { reason: string }).reason).toMatch(/did:mallory/);
    });

    it('should return invalid for non-existent delegation, and for a root whose parent is gone', () => {
      const graph = tree();
      expect(graph.validateChain('missing')).toMatchObject({ valid: false });
      graph.removeDelegation('a');
      expect(graph.validateChain('d')).toMatchObject({ valid: false, reason: expect.stringMatching(/parent a/) });
    });
  });

  describe('removeDelegation', () => {
    it('removes the node, unlinks it from its parent, and ignores an unknown id', () => {
      const graph = tree();
      graph.removeDelegation('c');
      expect(graph.getNode('c')).toBeNull();
      expect(graph.getNode('a')?.children).toEqual(['b']);
      graph.removeDelegation('missing');
      graph.removeDelegation('root');
      expect(graph.getNode('root')).toBeNull();
      graph.removeDelegation('a');
      expect(graph.size).toBe(2);
    });
  });

  describe('Helix hops', () => {
    const hop = (id: string, issuer: string, invoker: string, status = true): Record<string, unknown> => ({
      id,
      issuer,
      credentialSubject: { id: `${id}-cap`, invoker },
      ...(status ? { credentialStatus: { statusListCredential: 'https://l/1', statusListIndex: '3' } } : {}),
    });

    it('registers a chain root first, reads its chain string and continuity', () => {
      const graph = new DelegationGraph();
      const leaf = graph.registerChain([hop('vc-1', 'did:owner', 'did:agent'), hop('vc-2', 'did:agent', 'did:service', false)]);
      expect(leaf).toMatchObject({ id: 'vc-2', parentId: 'vc-1', capabilityId: 'vc-2-cap' });
      expect(graph.getNode('vc-1')?.credentialStatusId).toBe('https://l/1#3');
      expect(graph.chainString('vc-2')).toBe('vc-1>vc-1-cap>vc-2>vc-2-cap');
      expect(graph.validateChain('vc-2')).toEqual({ valid: true });
      graph.registerDelegation(node('bare', 'did:x', 'did:y'));
      expect(graph.chainString('bare')).toBe('bare');
    });

    it('reads `controller` when there is no invoker, and refuses what is not a hop or an empty chain', () => {
      expect(nodeOfHop({ id: 'v', issuer: 'did:a', credentialSubject: { controller: 'did:b' } })?.subjectDid).toBe('did:b');
      expect(nodeOfHop({ id: 'v', issuer: 'did:a', credentialSubject: {} })).toBeUndefined();
      expect(nodeOfHop('hop')).toBeUndefined();
      expect(() => new DelegationGraph().registerChain([{ id: 1 }])).toThrow(/hop 0/);
      expect(() => new DelegationGraph().registerChain([])).toThrow(/empty/);
    });
  });
});
