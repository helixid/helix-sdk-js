// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0

/**
 * The delegation graph a service keeps of the chains it has verified or
 * forwarded (KYA-OS story L3-D; SPEC.md §6.4; conformance L3.14 to L3.19):
 * every hop a node keyed by its credential id, linked to its parent.
 *
 * The middleware uses it for two things: the verification cache drops a
 * revoked credential's cached verdicts together with those of every
 * descendant (a revocation signal names one credential; its children fall
 * with it, §6.5 cascade), and a chain's string and root are read from it.
 * It is local state only, never a source of authority: every chain is
 * verified from its signed hops.
 */

export interface DelegationNode {
  /** The credential id (the hop's VC `id`). */
  id: string;
  /** The parent hop's credential id; absent on a root. */
  parentId?: string | undefined;
  /** Who issued the hop. */
  issuerDid: string;
  /** Who it delegates to (the ZCAP `invoker`). */
  subjectDid: string;
  /** The capability id (`credentialSubject.id`), for the chain string. */
  capabilityId?: string | undefined;
  /** The status entry's list URL and index, when the hop has one. */
  credentialStatusId?: string | undefined;
}

export interface DelegationGraphNode extends DelegationNode {
  children: string[];
}

export type ChainValidation = { valid: true } | { valid: false; reason: string };

const SAME_FIELDS = ['parentId', 'issuerDid', 'subjectDid', 'capabilityId', 'credentialStatusId'] as const;

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** A Helix hop (SPEC.md §6.10) as a graph node, or undefined when it is not shaped like one. */
export function nodeOfHop(hop: unknown, parentId?: string): DelegationNode | undefined {
  if (!isRecord(hop) || typeof hop['id'] !== 'string' || typeof hop['issuer'] !== 'string' || !isRecord(hop['credentialSubject'])) return undefined;
  const subject = hop['credentialSubject'];
  const invoker = typeof subject['invoker'] === 'string' ? subject['invoker'] : typeof subject['controller'] === 'string' ? subject['controller'] : undefined;
  if (invoker === undefined) return undefined;
  const status = isRecord(hop['credentialStatus']) ? hop['credentialStatus'] : undefined;
  const statusId =
    status !== undefined && typeof status['statusListCredential'] === 'string' && typeof status['statusListIndex'] === 'string'
      ? `${status['statusListCredential']}#${status['statusListIndex']}`
      : undefined;
  return {
    id: hop['id'],
    ...(parentId === undefined ? {} : { parentId }),
    issuerDid: hop['issuer'],
    subjectDid: invoker,
    ...(typeof subject['id'] === 'string' ? { capabilityId: subject['id'] } : {}),
    ...(statusId === undefined ? {} : { credentialStatusId: statusId }),
  };
}

export class DelegationGraph {
  readonly #nodes = new Map<string, DelegationGraphNode>();

  /** How many delegations the graph holds. */
  get size(): number {
    return this.#nodes.size;
  }

  /**
   * Registers a delegation (L3.14) and links it under its parent (L3.15).
   * Registering the same delegation again is a no-op that keeps its
   * children; a conflicting registration of an id, an unknown parent, or a
   * parent that is the node itself or one of its descendants throws.
   */
  registerDelegation(node: DelegationNode): DelegationGraphNode {
    const existing = this.#nodes.get(node.id);
    if (existing !== undefined) {
      const conflict = SAME_FIELDS.find((field) => existing[field] !== node[field]);
      if (conflict !== undefined) throw new Error(`delegation ${node.id} is already registered with another ${conflict}`);
      return existing;
    }
    if (node.parentId !== undefined) {
      if (node.parentId === node.id) throw new Error(`delegation ${node.id} cannot be its own parent`);
      const parent = this.#nodes.get(node.parentId);
      if (parent === undefined) throw new Error(`parent delegation ${node.parentId} is not registered`);
      if (!parent.children.includes(node.id)) parent.children.push(node.id);
    }
    const stored: DelegationGraphNode = { ...node, children: [] };
    this.#nodes.set(node.id, stored);
    return stored;
  }

  /** Registers a Helix chain, root first; returns the leaf node. Throws when a hop is not shaped like one. */
  registerChain(chain: readonly unknown[]): DelegationGraphNode {
    let parentId: string | undefined;
    let leaf: DelegationGraphNode | undefined;
    chain.forEach((hop, index) => {
      const node = nodeOfHop(hop, parentId);
      if (node === undefined) throw new Error(`hop ${index} is not a delegation credential`);
      leaf = this.registerDelegation(node);
      parentId = node.id;
    });
    if (leaf === undefined) throw new Error('an empty chain has no delegation to register');
    return leaf;
  }

  getNode(id: string): DelegationGraphNode | null {
    return this.#nodes.get(id) ?? null;
  }

  getChildren(id: string): DelegationGraphNode[] {
    return (this.#nodes.get(id)?.children ?? []).map((child) => this.#nodes.get(child)!).filter(Boolean);
  }

  /** Every descendant of `id`, depth first (L3.19). */
  getDescendants(id: string): DelegationGraphNode[] {
    const out: DelegationGraphNode[] = [];
    const seen = new Set<string>([id]);
    const walk = (current: string): void => {
      for (const child of this.getChildren(current)) {
        if (seen.has(child.id)) continue;
        seen.add(child.id);
        out.push(child);
        walk(child.id);
      }
    };
    walk(id);
    return out;
  }

  /** The chain from the root to `id`, root first (L3.18); empty when `id` is unknown. */
  getChain(id: string): DelegationGraphNode[] {
    const chain: DelegationGraphNode[] = [];
    const seen = new Set<string>();
    let current = this.#nodes.get(id);
    while (current !== undefined && !seen.has(current.id)) {
      seen.add(current.id);
      chain.unshift(current);
      current = current.parentId === undefined ? undefined : this.#nodes.get(current.parentId);
    }
    return chain;
  }

  /** Whether `ancestorId` is on the path from `id` to its root. */
  isAncestor(ancestorId: string, id: string): boolean {
    return this.getChain(id).some((node) => node.id === ancestorId && node.id !== id);
  }

  /** 0 for a root, 1 for its child, and so on; -1 when unknown. */
  getDepth(id: string): number {
    return this.getChain(id).length - 1;
  }

  /**
   * Issuer/subject continuity along the chain to `id` (L3.16, L3.17): each
   * child's issuer is its parent's subject, and each link agrees with the
   * order (the parent named is the node before it).
   */
  validateChain(id: string): ChainValidation {
    const chain = this.getChain(id);
    if (chain.length === 0) return { valid: false, reason: `delegation ${id} is not registered` };
    if (chain[0]!.parentId !== undefined) return { valid: false, reason: `the parent ${chain[0]!.parentId} of ${chain[0]!.id} is not registered` };
    for (let index = 1; index < chain.length; index += 1) {
      const parent = chain[index - 1]!;
      const child = chain[index]!;
      if (child.parentId !== parent.id) return { valid: false, reason: `${child.id} does not link to ${parent.id}` };
      if (child.issuerDid !== parent.subjectDid) {
        return { valid: false, reason: `${child.id} is issued by ${child.issuerDid}, not by ${parent.subjectDid}, the subject of its parent` };
      }
    }
    return { valid: true };
  }

  /** The §8.3 chain string to `id`: `<vcId>><capabilityId>` per hop, root first. */
  chainString(id: string): string {
    return this.getChain(id)
      .map((node) => (node.capabilityId === undefined ? node.id : `${node.id}>${node.capabilityId}`))
      .join('>');
  }

  /** Removes `id` and unlinks it from its parent; its children stay, orphaned. Unknown ids are ignored. */
  removeDelegation(id: string): void {
    const node = this.#nodes.get(id);
    if (node === undefined) return;
    if (node.parentId !== undefined) {
      const parent = this.#nodes.get(node.parentId);
      if (parent !== undefined) parent.children = parent.children.filter((child) => child !== id);
    }
    this.#nodes.delete(id);
  }
}

export function createDelegationGraph(): DelegationGraph {
  return new DelegationGraph();
}
