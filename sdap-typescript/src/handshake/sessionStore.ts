/**
 * In-memory session store for SDAP handshake sessions.
 */

import { Session, isSessionExpired } from "./protocol.js";

/**
 * In-memory store for Session objects.
 */
export class SessionStore {
  private sessions: Map<string, Session> = new Map();

  /**
   * Save a session by its sessionId.
   */
  store(session: Session): void {
    this.sessions.set(session.sessionId, session);
  }

  /**
   * Return the session for sessionId, or undefined if not found.
   */
  get(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Remove a session by sessionId (no-op if not present).
   */
  remove(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Remove all expired sessions.
   */
  cleanupExpired(): void {
    for (const [id, session] of this.sessions.entries()) {
      if (isSessionExpired(session)) {
        this.sessions.delete(id);
      }
    }
  }

  /**
   * Increment and return the next sequence number for senderDid in sessionId.
   *
   * Throws if the session is not found.
   */
  nextSequence(sessionId: string, senderDid: string): number {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const current = session.sequenceCounter[senderDid] ?? 0;
    const next = current + 1;
    session.sequenceCounter[senderDid] = next;
    return next;
  }

  /**
   * Return true if seq is strictly greater than the current counter for senderDid.
   *
   * Ensures monotonicity (no replay of old sequence numbers).
   *
   * Throws if the session is not found.
   */
  validateSequence(
    sessionId: string,
    senderDid: string,
    seq: number
  ): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const current = session.sequenceCounter[senderDid] ?? 0;
    return seq > current;
  }
}
