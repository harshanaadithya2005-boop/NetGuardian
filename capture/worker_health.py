
"""
NetGuardian - Capture Worker Health Tracker

Tracks worker state, packet activity and successful
core traffic persistence.

Thread-safe and in-memory only.

Does not write heartbeat records, start capture,
or modify any SQLite database.
"""

import threading
import time


class CaptureWorkerHealth:
    def __init__(self, max_write_age_seconds=75):
        if max_write_age_seconds <= 0:
            raise ValueError("Maximum write age must be positive")

        self.max_write_age_seconds = max_write_age_seconds
        self._lock = threading.Lock()

        self._running = False
        self._received = 0
        self._persisted = 0
        self._failures = 0

        self._last_received = None
        self._last_persisted = None
        self._last_error = None

        self._worker_error = None

    def start(self, now=None):
        """Initialize health state for a new worker run."""
        with self._lock:
            self._running = True
            self._received = 0
            self._persisted = 0
            self._failures = 0
            self._last_received = None
            self._last_persisted = None
            self._last_error = None
            self._worker_error = None

    def packet_received(self, now=None):
        """Record that the packet callback was invoked."""
        moment = time.monotonic() if now is None else now

        with self._lock:
            if self._running:
                self._received += 1
                self._last_received = moment

    def traffic_persisted(self, now=None):
        """
        Record a successful core traffic insert.

        Call ONLY after log_traffic() returns successfully.
        """
        moment = time.monotonic() if now is None else now

        with self._lock:
            if self._running:
                self._persisted += 1
                self._last_persisted = moment

    def persistence_failed(self, error=None, now=None):
        """Record a failed core traffic insert."""
        moment = time.monotonic() if now is None else now

        with self._lock:
            if self._running:
                self._failures += 1
                self._last_error = moment

    def stop(self, error=None):
        """Mark worker as stopped or failed."""
        with self._lock:
            self._running = False

            if error is not None:
                self._worker_error = type(error).__name__

    def snapshot(self, now=None):
        """
        Return worker health without modifying counters.

        CAPTURING means that this tracker reports a
        running worker with recent successful persistence
        and no subsequent persistence failure.

        It does not independently prove Scapy is alive.
        """
        moment = time.monotonic() if now is None else now

        with self._lock:
            last_write = self._last_persisted
            last_error = self._last_error

            recent_write = (
                last_write is not None
                and 0 <= moment - last_write
                <= self.max_write_age_seconds
            )

            unresolved_failure = (
                last_error is not None
                and (
                    last_write is None
                    or last_error >= last_write
                )
            )

            if not self._running:
                status = "STOPPED"

            elif self._worker_error is not None:
                status = "ERROR"

            elif unresolved_failure:
                status = "WRITE_ERROR"

            elif recent_write:
                status = "CAPTURING"

            else:
                status = "UNVERIFIED"

            return {
                "status": status,
                "running": self._running,
                "packets_received": self._received,
                "traffic_records_persisted": self._persisted,
                "persistence_failures": self._failures,
                "recent_successful_write": recent_write,
                "heartbeat_candidate": status == "CAPTURING",
                "worker_error": self._worker_error,
            }
