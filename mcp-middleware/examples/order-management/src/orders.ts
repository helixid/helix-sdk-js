// Copyright 2026 DgVerse LLP
// Licensed under the Apache License, Version 2.0

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

/**
 * The scope each tool needs. Passed to the middleware as `toolScopes`, so any
 * tool not listed here is denied before it runs (deny by default).
 */
export const TOOL_SCOPES: Record<string, string[]> = {
  lookup_order: ['orders:read'],
  refund_order: ['orders:admin'],
};

export interface Order {
  id: string;
  customer: string;
  items: Array<{ sku: string; quantity: number; unitPrice: number }>;
  total: number;
  currency: 'USD';
  status: 'paid' | 'shipped' | 'refunded';
  refundedAt?: string;
  refundReason?: string;
}

export type OrderStore = Map<string, Order>;

/** An in-memory store with a few demo orders. State resets on restart. */
export function createOrderStore(): OrderStore {
  const orders: Order[] = [
    {
      id: 'ORD-1001',
      customer: 'Asha Rao',
      items: [{ sku: 'KB-01', quantity: 1, unitPrice: 89 }],
      total: 89,
      currency: 'USD',
      status: 'shipped',
    },
    {
      id: 'ORD-1002',
      customer: 'Ben Ortiz',
      items: [
        { sku: 'MS-02', quantity: 2, unitPrice: 25 },
        { sku: 'PD-07', quantity: 1, unitPrice: 15 },
      ],
      total: 65,
      currency: 'USD',
      status: 'paid',
    },
  ];
  return new Map(orders.map((order) => [order.id, order]));
}

const orderId = z.string().regex(/^ORD-\d{4,}$/, 'expected an order id like ORD-1001');

function text(value: unknown, isError = false): CallToolResult {
  return {
    content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

/**
 * The tools themselves know nothing about identity: by the time a call reaches
 * them, the HTTP layer has already authenticated the caller and checked the
 * tool's scope (see app.ts).
 */
export function registerOrderTools(server: McpServer, store: OrderStore): void {
  server.registerTool(
    'lookup_order',
    {
      title: 'Look up an order',
      description: 'Returns an order by id: customer, items, total and status.',
      inputSchema: { orderId },
      annotations: { readOnlyHint: true },
    },
    async ({ orderId: id }) => {
      const order = store.get(id);
      return order ? text(order) : text(`Order ${id} not found`, true);
    },
  );

  server.registerTool(
    'refund_order',
    {
      title: 'Refund an order',
      description: 'Refunds an order in full. Requires the orders:admin scope.',
      inputSchema: { orderId, reason: z.string().min(1).max(200) },
      annotations: { destructiveHint: true, idempotentHint: false },
    },
    async ({ orderId: id, reason }) => {
      const order = store.get(id);
      if (!order) return text(`Order ${id} not found`, true);
      if (order.status === 'refunded') return text(`Order ${id} was already refunded`, true);
      const refunded: Order = { ...order, status: 'refunded', refundedAt: new Date().toISOString(), refundReason: reason };
      store.set(id, refunded);
      return text(refunded);
    },
  );
}
