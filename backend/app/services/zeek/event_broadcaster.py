"""In-process SSE Event Broadcaster.

Distributes live Zeek events to connected SSE clients without blocking the
ingestion pipeline.  Each client gets its own bounded asyncio.Queue; a slow
client's queue overflows silently (events dropped for that client only).

Sequence IDs use the format ``<session_id>:<counter>`` so that
``Last-Event-ID`` from a previous process session is never accidentally
matched against the current session's counter space.  SSE replay is
guaranteed only within the current process session.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BroadcastEvent:
    """A single event to distribute to SSE subscribers."""

    sequence_id: int
    session_id: str
    event_type: str  # e.g. "zeek_connection"
    data: Dict[str, Any]

    @property
    def sse_id(self) -> str:
        """Composite SSE id: ``<session_id>:<sequence_id>``."""
        return f"{self.session_id}:{self.sequence_id}"

    def to_sse_data(self) -> str:
        """Serialise the event payload as a JSON string for SSE ``data:`` field."""
        payload = {
            "sequence_id": self.sequence_id,
            "session_id": self.session_id,
            **self.data,
        }
        return json.dumps(payload, default=str)


@dataclass
class SubscriberHandle:
    """Bookkeeping for a single SSE subscriber."""

    subscriber_id: str
    queue: asyncio.Queue  # bounded per-client queue
    dropped_events: int = 0


class EventBroadcaster:
    """Broadcast Zeek events to SSE subscribers with ring-buffer replay."""

    def __init__(
        self,
        *,
        max_clients: int = 32,
        client_queue_size: int = 128,
        replay_buffer_size: int = 256,
    ):
        self._session_id: str = uuid.uuid4().hex[:12]
        self._sequence_counter: int = 0
        self._max_clients = max_clients
        self._client_queue_size = client_queue_size

        self._subscribers: Dict[str, SubscriberHandle] = {}
        self._replay_buffer: Deque[BroadcastEvent] = collections.deque(
            maxlen=replay_buffer_size or 1
        )
        self._lock = asyncio.Lock()

        logger.info(
            "EventBroadcaster initialised: session=%s, max_clients=%d, replay_buffer=%d",
            self._session_id,
            max_clients,
            replay_buffer_size,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def client_count(self) -> int:
        return len(self._subscribers)

    @property
    def total_events_published(self) -> int:
        return self._sequence_counter

    @property
    def total_events_dropped(self) -> int:
        return sum(s.dropped_events for s in self._subscribers.values())

    # ------------------------------------------------------------------
    # Subscribe / Unsubscribe
    # ------------------------------------------------------------------

    async def subscribe(
        self, last_event_id: Optional[str] = None
    ) -> Tuple[str, asyncio.Queue]:
        """Register a new SSE subscriber.

        Returns ``(subscriber_id, queue)`` — the caller reads from the queue.

        Raises ``RuntimeError`` if the client cap is reached.
        """
        async with self._lock:
            if len(self._subscribers) >= self._max_clients:
                raise RuntimeError(
                    f"SSE client cap reached ({self._max_clients})"
                )

            sub_id = uuid.uuid4().hex[:12]
            q: asyncio.Queue = asyncio.Queue(maxsize=self._client_queue_size)
            handle = SubscriberHandle(subscriber_id=sub_id, queue=q)
            self._subscribers[sub_id] = handle

            # Replay from ring buffer if the client reconnected within
            # the same process session.
            replayed = 0
            if last_event_id:
                replayed = await self._replay_to_queue(q, last_event_id)

            logger.info(
                "SSE subscriber %s connected (total=%d, replayed=%d)",
                sub_id,
                len(self._subscribers),
                replayed,
            )
            return sub_id, q

    async def unsubscribe(self, subscriber_id: str) -> None:
        """Remove a subscriber (e.g. on client disconnect)."""
        async with self._lock:
            handle = self._subscribers.pop(subscriber_id, None)
            if handle:
                logger.info(
                    "SSE subscriber %s disconnected (total=%d, dropped=%d)",
                    subscriber_id,
                    len(self._subscribers),
                    handle.dropped_events,
                )

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    async def broadcast(self, event_type: str, data: Dict[str, Any]) -> BroadcastEvent:
        """Publish an event to all subscribers (non-blocking for slow clients).

        Returns the ``BroadcastEvent`` with its assigned sequence ID.
        """
        async with self._lock:
            self._sequence_counter += 1
            event = BroadcastEvent(
                sequence_id=self._sequence_counter,
                session_id=self._session_id,
                event_type=event_type,
                data=data,
            )
            self._replay_buffer.append(event)

            for handle in self._subscribers.values():
                try:
                    handle.queue.put_nowait(event)
                except asyncio.QueueFull:
                    handle.dropped_events += 1

        return event

    # ------------------------------------------------------------------
    # Ring-buffer replay
    # ------------------------------------------------------------------

    async def _replay_to_queue(
        self, queue: asyncio.Queue, last_event_id: str
    ) -> int:
        """Replay missed events from the ring buffer into a subscriber queue.

        ``last_event_id`` format: ``<session_id>:<sequence_id>``

        If the session_id doesn't match the current session, no replay is
        performed (the client must recover via the historical telemetry API).
        """
        parts = last_event_id.rsplit(":", 1)
        if len(parts) != 2:
            return 0

        req_session, seq_str = parts
        if req_session != self._session_id:
            # Different process session — replay not possible
            logger.info(
                "Last-Event-ID session %s != current %s; skipping replay",
                req_session,
                self._session_id,
            )
            return 0

        try:
            last_seq = int(seq_str)
        except ValueError:
            return 0

        replayed = 0
        for event in self._replay_buffer:
            if event.sequence_id > last_seq:
                try:
                    queue.put_nowait(event)
                    replayed += 1
                except asyncio.QueueFull:
                    break
        return replayed
