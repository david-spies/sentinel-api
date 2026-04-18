"""
ai/core/event_bus.py

In-memory pub/sub event bus for real-time scan event fan-out.

The Go orchestrator pushes ScanEvent messages via the gRPC StreamScanEvents
RPC. The event bus receives them and broadcasts to all WebSocket clients
currently subscribed to that scan_id.

Architecture:
  Go scanner
      │  gRPC StreamScanEvents (client-streaming)
      ▼
  grpc/server.py → publish_event()
      │
      ▼
  EventBus (asyncio.Queue per subscriber)
      │  asyncio
      ▼
  FastAPI WebSocket endpoint (/ws/scan/{scan_id})
      │
      ▼
  Dashboard browser (live log stream + progress bar update)

Thread safety:
  publish_event() is called from the gRPC thread pool (sync context).
  It uses asyncio.run_coroutine_threadsafe() to safely enqueue onto the
  async event loop without blocking the gRPC worker.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanEvent:
    scan_id:  str
    phase:    str
    message:  str
    done:     int = 0
    total:    int = 0
    ts_ms:    int = field(default_factory=lambda: int(time.time() * 1000))
    severity: str = "INFO"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "phase":   self.phase,
            "message": self.message,
            "done":    self.done,
            "total":   self.total,
            "ts_ms":   self.ts_ms,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------

class EventBus:
    """
    Thread-safe, asyncio-compatible event bus.

    Subscribers receive a asyncio.Queue[ScanEvent | None].
    None is the sentinel that signals the stream has ended.
    """

    def __init__(self) -> None:
        # scan_id → list of subscriber queues
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the asyncio event loop. Must be called from the async context."""
        self._loop = loop

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """
        Register a new subscriber for scan_id.
        Returns a Queue the subscriber should read from.
        The subscriber is responsible for calling unsubscribe() when done.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._lock:
            self._subscribers[scan_id].append(q)
        logger.debug("event_bus_subscribe", scan_id=scan_id, subscribers=len(self._subscribers[scan_id]))
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        """Remove a subscriber queue."""
        with self._lock:
            subs = self._subscribers.get(scan_id, [])
            if q in subs:
                subs.remove(q)
            if not subs:
                self._subscribers.pop(scan_id, None)
        logger.debug("event_bus_unsubscribe", scan_id=scan_id)

    def publish_sync(self, event: ScanEvent) -> None:
        """
        Publish an event from a synchronous (gRPC) context.
        Uses run_coroutine_threadsafe to safely schedule the async enqueue.
        """
        if self._loop is None or not self._loop.is_running():
            logger.warning("event_bus_no_loop", scan_id=event.scan_id)
            return

        asyncio.run_coroutine_threadsafe(self._enqueue(event), self._loop)

    async def publish_async(self, event: ScanEvent) -> None:
        """Publish an event from an async context (FastAPI route)."""
        await self._enqueue(event)

    async def _enqueue(self, event: ScanEvent) -> None:
        with self._lock:
            queues = list(self._subscribers.get(event.scan_id, []))

        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("event_bus_queue_full", scan_id=event.scan_id)

    async def close_scan(self, scan_id: str) -> None:
        """Signal all subscribers that a scan stream has ended."""
        with self._lock:
            queues = list(self._subscribers.get(scan_id, []))
        for q in queues:
            try:
                q.put_nowait(None)  # sentinel
            except asyncio.QueueFull:
                pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_bus = EventBus()


def get_event_bus() -> EventBus:
    return _bus


def publish_event(
    scan_id: str,
    phase: str,
    message: str,
    done: int = 0,
    total: int = 0,
    severity: str = "INFO",
) -> None:
    """
    Convenience function called by grpc/server.py StreamScanEvents handler.
    Publishes from the gRPC thread pool into the asyncio event loop.
    """
    event = ScanEvent(
        scan_id=scan_id,
        phase=phase,
        message=message,
        done=done,
        total=total,
        severity=severity,
    )
    _bus.publish_sync(event)
