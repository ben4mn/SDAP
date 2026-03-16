"""In-memory session store for SDAP handshake sessions."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Optional

from sdap.handshake.protocol import Session


class SessionStore:
    """Thread-safe in-memory store for :class:`Session` objects."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = Lock()

    def store(self, session: Session) -> None:
        """Save a session by its session_id."""
        with self._lock:
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> Optional[Session]:
        """Return the session for *session_id*, or None if not found."""
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: str) -> None:
        """Remove a session by session_id (no-op if not present)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def cleanup_expired(self) -> None:
        """Remove all expired sessions."""
        now = datetime.now(tz=timezone.utc)
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.expiry <= now]
            for sid in expired:
                del self._sessions[sid]

    def next_sequence(self, session_id: str, sender_did: str) -> int:
        """Increment and return the next sequence number for *sender_did* in *session_id*.

        Raises:
            KeyError: If the session is not found.
        """
        with self._lock:
            session = self._sessions[session_id]
            current = session.sequence_counter.get(sender_did, 0)
            next_seq = current + 1
            session.sequence_counter[sender_did] = next_seq
            return next_seq

    def validate_sequence(self, session_id: str, sender_did: str, seq: int) -> bool:
        """Return True if *seq* is strictly greater than the current counter for *sender_did*.

        This ensures monotonicity (no replay of old sequence numbers).

        Raises:
            KeyError: If the session is not found.
        """
        with self._lock:
            session = self._sessions[session_id]
            current = session.sequence_counter.get(sender_did, 0)
            return seq > current
