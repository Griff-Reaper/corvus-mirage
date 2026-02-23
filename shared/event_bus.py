"""
Corvus Mirage — Shared
Event Bus

Async pub/sub for real-time cross-component event broadcasting.
When Gateway blocks an attack, ARIA's WebSocket clients hear about it
immediately — and vice versa. The unified dashboard subscribes to
all events from a single connection.

Usage:
    # Publishing (from Gateway or ARIA after detection):
    from shared.event_bus import get_event_bus
    await get_event_bus().publish("threat_detected", event.to_dict())

    # Subscribing (dashboard WebSocket handler):
    bus = get_event_bus()
    queue = await bus.subscribe()
    try:
        while True:
            event_type, data = await queue.get()
            await websocket.send_json({"event": event_type, "data": data})
    finally:
        await bus.unsubscribe(queue)
"""
import asyncio
import logging
from typing import Dict, Any, Set, Tuple

logger = logging.getLogger("corvus.shared.event_bus")


class EventBus:
    """
    In-process async pub/sub.
    Subscribers receive all events published after they subscribe.
    Each subscriber gets its own asyncio.Queue so slow consumers
    don't block fast ones.
    """

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()
        self._published_count = 0

    async def subscribe(self) -> asyncio.Queue:
        """Register a new subscriber. Returns the queue to read from."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(queue)
        logger.debug(f"Subscriber added | total={len(self._subscribers)}")
        return queue

    async def unsubscribe(self, queue: asyncio.Queue):
        """Remove a subscriber."""
        async with self._lock:
            self._subscribers.discard(queue)
        logger.debug(f"Subscriber removed | total={len(self._subscribers)}")

    async def publish(self, event_type: str, data: Dict[str, Any]):
        """
        Publish an event to all subscribers.

        Args:
            event_type: e.g. "threat_detected", "prompt_blocked",
                        "vishing_alert", "cross_vector_hit"
            data:       Serializable dict payload
        """
        if not self._subscribers:
            return

        self._published_count += 1
        dead = set()

        async with self._lock:
            subscribers = set(self._subscribers)

        for queue in subscribers:
            try:
                queue.put_nowait((event_type, data))
            except asyncio.QueueFull:
                # Slow subscriber — drop oldest event and retry
                try:
                    queue.get_nowait()
                    queue.put_nowait((event_type, data))
                except Exception:
                    dead.add(queue)
            except Exception:
                dead.add(queue)

        if dead:
            async with self._lock:
                self._subscribers -= dead
            logger.debug(f"Removed {len(dead)} dead subscriber(s)")

        logger.debug(
            f"Published: {event_type} | "
            f"subscribers={len(self._subscribers)} | "
            f"total_published={self._published_count}"
        )

    async def publish_threat(self, source: str, data: Dict[str, Any]):
        """Shortcut for malicious threat events."""
        await self.publish(f"{source}_threat_detected", data)

    async def publish_block(self, source: str, data: Dict[str, Any]):
        """Shortcut for blocked events."""
        await self.publish(f"{source}_blocked", data)

    async def publish_cross_vector(self, session_id: str, data: Dict[str, Any]):
        """
        Published when the same session_id appears in both ARIA and Gateway.
        Highest priority alert — attacker operating across multiple vectors.
        """
        await self.publish("cross_vector_attack", {
            "session_id": session_id,
            **data
        })

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def published_count(self) -> int:
        return self._published_count


# Singleton — one bus for the whole process
_bus: EventBus = None

def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
        logger.info("[✓] Shared event bus initialized")
    return _bus
