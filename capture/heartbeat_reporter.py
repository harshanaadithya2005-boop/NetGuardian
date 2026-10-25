
"""
NetGuardian - Rate-Limited Capture Heartbeat Reporter

Records at most one successful heartbeat per worker
per minute, except that ERROR may upgrade CAPTURING.

A failure in heartbeat storage does not crash capture.

Requires an explicitly supplied connection factory.
Does not start threads or connect automatically.
"""

import threading
from datetime import datetime

from capture.heartbeat_bridge import (
    heartbeat_status_for_snapshot,
    persist_health_heartbeat
)


class CaptureHeartbeatReporter:

    def __init__(
        self,
        connection_factory,
        worker_name="packet_capture"
    ):
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")

        if not isinstance(worker_name, str) or not worker_name.strip():
            raise ValueError("Invalid worker name")

        self.connection_factory = connection_factory
        self.worker_name = worker_name.strip()

        self._lock = threading.Lock()
        self._last_minute = None
        self._last_status = None

    def report(self, snapshot, recorded_at=None):
        """
        Attempt heartbeat reporting without propagating
        database exceptions to the capture worker.
        """

        moment = (
            datetime.now()
            if recorded_at is None
            else recorded_at
        )

        if not isinstance(moment, datetime):
            raise TypeError("recorded_at must be datetime")

        if moment.tzinfo is not None:
            raise ValueError("Use local naive timestamps")

        minute = moment.replace(
            second=0,
            microsecond=0
        )

        status = heartbeat_status_for_snapshot(snapshot)

        if status is None:
            return {
                "status": "NOT_RECORDED",
                "written": False
            }

        with self._lock:

            # Avoid repeated healthy writes in one minute.
            # However, permit ERROR to upgrade CAPTURING.
            if self._last_minute == minute:
                if self._last_status == "ERROR":
                    return {
                        "status": "ALREADY_REPORTED",
                        "written": False
                    }

                if (
                    self._last_status == "CAPTURING"
                    and status == "CAPTURING"
                ):
                    return {
                        "status": "ALREADY_REPORTED",
                        "written": False
                    }

            conn = None

            try:
                conn = self.connection_factory()

                result = persist_health_heartbeat(
                    conn=conn,
                    snapshot=snapshot,
                    recorded_at=moment,
                    worker_name=self.worker_name
                )

                conn.commit()

                # Advance the rate limiter only after
                # a successful database transaction.
                self._last_minute = minute
                self._last_status = status

                return {
                    "status": status,
                    "written": (
                        result.get("inserted", False)
                        or result.get("updated", False)
                    )
                }

            except Exception as error:
                if conn is not None:
                    try:
                        conn.rollback()
                    except Exception:
                        pass

                return {
                    "status": "HEARTBEAT_WRITE_FAILED",
                    "written": False,
                    "error_type": type(error).__name__
                }

            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
