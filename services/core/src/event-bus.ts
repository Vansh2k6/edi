import type { Decision } from '@pv/schemas';
import { toWireDecision, type StoredDecision } from './decision-service.js';

/**
 * Live decision events (W8.3).
 *
 * A tiny per-owner pub/sub. The decision service publishes after it records;
 * the SSE route subscribes for one owner's session. Events carry exactly what
 * a decision record carries - never request bodies, vault plaintext or
 * anything the dashboard would not already be allowed to show. Frames hold
 * the shared wire shape (no storage-only fields), so the client's schema
 * validation passes by construction.
 */

export type DecisionEvent = { type: 'decision'; decision: Decision };

export type DecisionListener = (event: DecisionEvent) => void;

export class DecisionEventBus {
  readonly #listeners = new Map<string, Set<DecisionListener>>();

  /** Subscribe to one owner's events. The returned function unsubscribes. */
  subscribe(userId: string, listener: DecisionListener): () => void {
    let set = this.#listeners.get(userId);
    if (set === undefined) {
      set = new Set();
      this.#listeners.set(userId, set);
    }
    set.add(listener);
    return () => {
      set!.delete(listener);
      if (set!.size === 0) this.#listeners.delete(userId);
    };
  }

  /** Deliver an event to every listener of exactly this owner. Storage-only fields are stripped at this boundary. */
  publish(userId: string, event: { type: 'decision'; decision: StoredDecision }): void {
    const wire: DecisionEvent = { type: event.type, decision: toWireDecision(event.decision) };
    const set = this.#listeners.get(userId);
    if (set === undefined) return;
    for (const listener of set) {
      // One broken subscriber must not starve the others; stream consumers
      // handle their own socket errors.
      try {
        listener(wire);
      } catch {
        // ignore: a failed SSE write is cleaned up by the close handler
      }
    }
  }
}

/**
 * SSE adapter shared by the stream route and its tests.
 *
 * Takes the *raw* response and owns the entire response head: it sets the SSE
 * headers and its first write flushes the 200. The caller must have hijacked
 * the reply and must not touch headers itself - a writeHead before this call
 * makes the later setHeader throw ERR_HTTP_HEADERS_SENT and the socket hang
 * with no response (observed live). After `reply.hijack()` Fastify no longer
 * manages (or clobbers) headers, so the stream is written straight to the
 * socket until the client disconnects.
 */
export function streamDecisions(
  raw: { setHeader: (name: string, value: string) => unknown; write: (chunk: string) => unknown; on: (event: 'close', cb: () => void) => unknown; headersSent?: boolean },
  bus: DecisionEventBus,
  userId: string,
): () => void {
  // Fail loudly rather than hang the socket in a half-sent state.
  if (raw.headersSent === true) {
    throw new Error('streamDecisions must own the response head; the caller already sent headers');
  }
  raw.setHeader('content-type', 'text/event-stream');
  raw.setHeader('cache-control', 'no-store');
  raw.setHeader('connection', 'keep-alive');
  // A comment frame so the client connects before the first real event.
  raw.write(': connected\n\n');
  const unsubscribe = bus.subscribe(userId, (event) => {
    raw.write(`event: ${event.type}\ndata: ${JSON.stringify(event.decision)}\n\n`);
  });
  const onClose = (): void => unsubscribe();
  raw.on('close', onClose);
  return unsubscribe;
}
