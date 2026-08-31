"""Tests for SSE EventBroadcaster.

Verifies:
- Subscription and unsubscription lifecycle
- Broadcast distribution to multiple connected clients
- Slow client non-blocking drop behaviour
- Session-scoped composite sequence IDs (<session_id>:<sequence_id>)
- Last-Event-ID replay within same session
- No replay across different process sessions
- Client cap enforcement (HTTP 429 semantics)
"""

import asyncio
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.zeek.event_broadcaster import EventBroadcaster


class TestEventBroadcaster(unittest.IsolatedAsyncioTestCase):
    """Unit tests for EventBroadcaster."""

    async def test_subscribe_and_broadcast(self):
        """Single subscriber receives broadcast event with session-scoped ID."""
        broadcaster = EventBroadcaster(max_clients=5, client_queue_size=10)
        sub_id, queue = await broadcaster.subscribe()

        self.assertEqual(broadcaster.client_count, 1)

        event = await broadcaster.broadcast("zeek_connection", {"uid": "U123"})

        self.assertEqual(event.sequence_id, 1)
        self.assertTrue(event.sse_id.startswith(broadcaster.session_id + ":1"))

        received = await asyncio.wait_for(queue.get(), timeout=1.0)
        self.assertEqual(received.sequence_id, 1)
        self.assertEqual(received.data["uid"], "U123")

        await broadcaster.unsubscribe(sub_id)
        self.assertEqual(broadcaster.client_count, 0)

    async def test_broadcast_to_multiple_clients(self):
        """All subscribers receive broadcast events."""
        broadcaster = EventBroadcaster(max_clients=5, client_queue_size=10)
        sub1, q1 = await broadcaster.subscribe()
        sub2, q2 = await broadcaster.subscribe()

        await broadcaster.broadcast("zeek_connection", {"uid": "U_MULTI"})

        r1 = await asyncio.wait_for(q1.get(), timeout=1.0)
        r2 = await asyncio.wait_for(q2.get(), timeout=1.0)
        self.assertEqual(r1.data["uid"], "U_MULTI")
        self.assertEqual(r2.data["uid"], "U_MULTI")

        await broadcaster.unsubscribe(sub1)
        await broadcaster.unsubscribe(sub2)

    async def test_slow_client_drop_does_not_block_others(self):
        """When a client queue is full, events are dropped silently for that client without blocking."""
        broadcaster = EventBroadcaster(max_clients=5, client_queue_size=2)
        sub_slow, q_slow = await broadcaster.subscribe()
        sub_fast, q_fast = await broadcaster.subscribe()

        # Broadcast 1 & 2
        await broadcaster.broadcast("zeek_connection", {"seq": 1})
        await broadcaster.broadcast("zeek_connection", {"seq": 2})

        # Fast client consumes its items
        item1 = await q_fast.get()
        item2 = await q_fast.get()
        self.assertEqual(item1.data["seq"], 1)
        self.assertEqual(item2.data["seq"], 2)

        # Broadcast 3: slow client's queue is full (size 2), so it drops; fast client has room
        await broadcaster.broadcast("zeek_connection", {"seq": 3})

        self.assertEqual(broadcaster.total_events_dropped, 1)
        self.assertEqual(q_slow.qsize(), 2)

        # Fast client receives event 3
        item3 = await q_fast.get()
        self.assertEqual(item3.data["seq"], 3)

        await broadcaster.unsubscribe(sub_slow)
        await broadcaster.unsubscribe(sub_fast)

    async def test_ring_buffer_replay_same_session(self):
        """Client reconnecting with Last-Event-ID gets missed events replayed."""
        broadcaster = EventBroadcaster(max_clients=5, replay_buffer_size=10)

        # Broadcast 3 events before subscriber connects
        await broadcaster.broadcast("zeek_connection", {"idx": 1})
        await broadcaster.broadcast("zeek_connection", {"idx": 2})
        await broadcaster.broadcast("zeek_connection", {"idx": 3})

        # Subscriber reconnects specifying they last saw event 1
        last_id = f"{broadcaster.session_id}:1"
        sub_id, queue = await broadcaster.subscribe(last_event_id=last_id)

        # Should receive events 2 and 3 from replay buffer
        self.assertEqual(queue.qsize(), 2)
        e2 = await queue.get()
        e3 = await queue.get()
        self.assertEqual(e2.data["idx"], 2)
        self.assertEqual(e3.data["idx"], 3)

        await broadcaster.unsubscribe(sub_id)

    async def test_no_replay_different_session(self):
        """Last-Event-ID from a different process session is not replayed."""
        broadcaster = EventBroadcaster(max_clients=5, replay_buffer_size=10)

        await broadcaster.broadcast("zeek_connection", {"idx": 1})

        # Reconnect with a different session ID
        different_last_id = "old_session_123:1"
        sub_id, queue = await broadcaster.subscribe(last_event_id=different_last_id)

        # No replay should happen
        self.assertEqual(queue.qsize(), 0)

        await broadcaster.unsubscribe(sub_id)

    async def test_max_client_cap_enforcement(self):
        """Subscribe raises RuntimeError when client cap is reached."""
        broadcaster = EventBroadcaster(max_clients=2, client_queue_size=5)
        sub1, _ = await broadcaster.subscribe()
        sub2, _ = await broadcaster.subscribe()

        with self.assertRaises(RuntimeError):
            await broadcaster.subscribe()

        await broadcaster.unsubscribe(sub1)
        # Now slot is free
        sub3, _ = await broadcaster.subscribe()
        self.assertEqual(broadcaster.client_count, 2)

        await broadcaster.unsubscribe(sub2)
        await broadcaster.unsubscribe(sub3)


if __name__ == "__main__":
    unittest.main()
