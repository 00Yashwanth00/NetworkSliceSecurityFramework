#!/usr/bin/env python3
"""
packet_collector_live.py

Continuous live packet collector that publishes completed flows to Redis
and simultaneously writes them to a local CSV backup.

The collector uses CICFlowMeter's live-capture sniffer and FlowSession.
Completed flows are written when CICFlowMeter determines that a flow has
ended/expired.

Key properties:
  - Live packet capture
  - CICFlowMeter flow feature extraction
  - Redis Stream publishing
  - Local CSV backup
  - Redis publishing happens in a background thread
  - Redis failures do not stop packet capture
  - Periodic garbage collection for low-traffic interfaces
  - 15-second idle timeout
  - NumPy scalar values are converted to native Python values before
    publishing to Redis

Usage:

    python packet_collector_live.py \
        --interface eth0 \
        --redis-host localhost \
        --redis-port 6379 \
        --stream telemetry.packet \
        --csv-backup ./live_flows_backup.csv

Example with a session label:

    python packet_collector_live.py \
        --interface eth0 \
        --session-label signaling_storm \
        --redis-host localhost \
        --redis-port 6379
"""

import argparse
import csv
import json
import logging
import queue
import threading
import time
from pathlib import Path

import cicflowmeter.constants as _cfc
import cicflowmeter.flow_session as _cffs
from cicflowmeter.sniffer import create_sniffer


# ---------------------------------------------------------------------------
# CICFlowMeter configuration
# ---------------------------------------------------------------------------

# CICFlowMeter's default expiration interval is much larger than desirable
# for live inference. Reduce it to 15 seconds.
#
# flow_session.py imports EXPIRED_UPDATE at module load time, so both the
# constants module and the already-imported flow_session symbol must be patched.
# ---------------------------------------------------------------------------

_IDLE_TIMEOUT_SEC = 15

_cfc.EXPIRED_UPDATE = _IDLE_TIMEOUT_SEC
_cffs.EXPIRED_UPDATE = _IDLE_TIMEOUT_SEC


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("packet_collector_live")


# ---------------------------------------------------------------------------
# Redis-safe value conversion
# ---------------------------------------------------------------------------

def _redis_safe_value(value):
    """
    Convert CICFlowMeter / NumPy values into values accepted by Redis.

    In particular:

        np.float64(74.0) -> 74.0
        np.int64(74)     -> 74

    Redis Streams accept strings, bytes, integers and floats, but NumPy
    scalar objects can otherwise end up being represented as strings such as:

        'np.float64(74.0)'

    which later causes the inference service to fail when it executes:

        float('np.float64(74.0)')

    This function converts NumPy scalar values through their .item()
    method before publishing.

    Dictionaries and lists are JSON encoded recursively.
    """

    if value is None:
        return ""

    # NumPy scalar types, e.g. np.float64, np.int64, np.bool_
    #
    # NumPy scalar objects expose .item(), which returns the equivalent
    # native Python scalar.
    if hasattr(value, "item"):
        try:
            return value.item()
        except (ValueError, TypeError):
            pass

    # Handle dictionaries recursively.
    if isinstance(value, dict):
        return json.dumps(
            {
                key: _redis_safe_value(val)
                for key, val in value.items()
            }
        )

    # Handle lists/tuples recursively.
    if isinstance(value, (list, tuple)):
        return json.dumps(
            [
                _redis_safe_value(val)
                for val in value
            ]
        )

    return value


# ---------------------------------------------------------------------------
# DualWriter
# ---------------------------------------------------------------------------

class DualWriter:
    """
    Output writer compatible with CICFlowMeter's OutputWriter protocol.

    Every completed flow is:

      1. Written synchronously to a local CSV backup.
      2. Added to a bounded queue for asynchronous Redis publishing.

    The CSV write is deliberately synchronous so that the local backup
    remains available even if Redis is unavailable.

    Redis publishing is asynchronous so a slow broker cannot block the
    packet-capture thread.
    """

    def __init__(
        self,
        csv_backup_path: str,
        publish_fn,
        session_label: str,
        queue_maxsize: int = 10000,
    ):
        self._csv_path = Path(csv_backup_path)
        self._csv_file = None
        self._csv_writer = None
        self._csv_header_written = False

        self._publish_fn = publish_fn
        self._session_label = session_label

        self._q = queue.Queue(maxsize=queue_maxsize)

        self._dropped = 0
        self._published = 0

        self._stop = threading.Event()

        self._worker = threading.Thread(
            target=self._publish_loop,
            daemon=True,
            name="broker-publish",
        )

        self._worker.start()

    # -----------------------------------------------------------------------
    # Redis publishing worker
    # -----------------------------------------------------------------------

    def _publish_loop(self):
        while not self._stop.is_set() or not self._q.empty():
            try:
                data = self._q.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._publish_fn(data)
                self._published += 1

            except Exception:
                logger.exception(
                    "Failed to publish flow to broker; "
                    "flow is still available in the CSV backup"
                )

            finally:
                self._q.task_done()

    # -----------------------------------------------------------------------
    # CICFlowMeter OutputWriter interface
    # -----------------------------------------------------------------------

    def write(self, data: dict) -> None:
        """
        Receive a completed CICFlowMeter flow.

        The flow is augmented with session metadata, written to CSV,
        then queued for Redis publishing.
        """

        # Copy so we don't modify CICFlowMeter's original dictionary.
        data = dict(data)

        # Add pipeline metadata.
        data["sessionLabel"] = self._session_label
        data["captured_at"] = time.time()

        # -------------------------------------------------------------------
        # Local CSV backup
        # -------------------------------------------------------------------

        if self._csv_file is None:
            # Make sure the parent directory exists.
            self._csv_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            self._csv_file = open(
                self._csv_path,
                "w",
                newline="",
            )

            self._csv_writer = csv.writer(self._csv_file)

        if not self._csv_header_written:
            self._csv_writer.writerow(data.keys())
            self._csv_header_written = True

        self._csv_writer.writerow(data.values())
        self._csv_file.flush()

        # -------------------------------------------------------------------
        # Redis publish queue
        # -------------------------------------------------------------------

        try:
            self._q.put_nowait(data)

        except queue.Full:
            self._dropped += 1

            if self._dropped % 100 == 1:
                logger.warning(
                    "Broker publish queue full -- "
                    f"{self._dropped} flow(s) dropped from streaming so far "
                    "(still present in the CSV backup)"
                )

    # -----------------------------------------------------------------------
    # Statistics
    # -----------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "published": self._published,
            "dropped_from_queue": self._dropped,
            "queue_depth": self._q.qsize(),
        }

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    def close(self):
        """
        Stop the Redis worker and close the CSV file.
        """

        self._stop.set()

        self._worker.join(timeout=5.0)

        if self._csv_file:
            self._csv_file.close()
            self._csv_file = None


# ---------------------------------------------------------------------------
# Redis publisher
# ---------------------------------------------------------------------------

def make_redis_publish_fn(
    host: str,
    port: int,
    stream: str,
):
    """
    Create a Redis Stream publisher.

    Redis is connected once and checked with PING during startup.

    Each completed flow is converted into Redis-safe values before being
    passed to XADD.
    """

    import redis

    client = redis.Redis(
        host=host,
        port=port,
        decode_responses=True,
    )

    # Fail fast during startup if Redis is unavailable.
    client.ping()

    logger.info(
        f"Connected to Redis at {host}:{port}, "
        f"publishing to stream '{stream}'"
    )

    def publish(data: dict):
        """
        Publish one completed flow to the Redis Stream.
        """

        # IMPORTANT FIX:
        #
        # Convert NumPy scalars such as:
        #
        #     np.float64(74.0)
        #
        # into:
        #
        #     74.0
        #
        # before Redis receives them.
        flat = {
            key: _redis_safe_value(value)
            for key, value in data.items()
        }

        client.xadd(stream, flat)

    return publish


# ---------------------------------------------------------------------------
# Background flow garbage collection
# ---------------------------------------------------------------------------

def run_gc_thread(
    session,
    stop_event: threading.Event,
    interval: float = 10.0,
):
    """
    Periodically force CICFlowMeter to garbage-collect expired flows.

    CICFlowMeter normally performs garbage collection based on packet count.
    On a low-traffic interface, that can leave completed/idle flows sitting
    in memory for too long.

    Calling garbage_collect() periodically ensures that flows exceeding
    EXPIRED_UPDATE are emitted promptly.
    """

    while not stop_event.wait(timeout=interval):
        try:
            session.garbage_collect(time.time())

        except Exception:
            logger.exception(
                "GC thread hit an unexpected error"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Live packet-level flow collector, "
            "streaming completed flows to Redis"
        )
    )

    parser.add_argument(
        "--interface",
        required=True,
        help="Network interface to capture on",
    )

    parser.add_argument(
        "--redis-host",
        default="localhost",
        help="Redis server hostname",
    )

    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
        help="Redis server port",
    )

    parser.add_argument(
        "--stream",
        default="telemetry.packet",
        help="Redis Stream name",
    )

    parser.add_argument(
        "--csv-backup",
        default="./live_flows_backup.csv",
        help=(
            "Local CSV path where every completed flow "
            "is also written"
        ),
    )

    parser.add_argument(
        "--session-label",
        default="normal",
        help=(
            "Session label attached to every published flow "
            "(mirrors collector.sessionLabel)"
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Logging setup
    # -----------------------------------------------------------------------

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=(
            "%(asctime)s [%(levelname)s] "
            "%(name)s: %(message)s"
        ),
    )

    # -----------------------------------------------------------------------
    # Redis publisher
    # -----------------------------------------------------------------------

    publish_fn = make_redis_publish_fn(
        args.redis_host,
        args.redis_port,
        args.stream,
    )

    # -----------------------------------------------------------------------
    # Dual writer
    # -----------------------------------------------------------------------

    writer = DualWriter(
        args.csv_backup,
        publish_fn,
        args.session_label,
    )

    # -----------------------------------------------------------------------
    # CICFlowMeter sniffer/session
    # -----------------------------------------------------------------------

    sniffer, session = create_sniffer(
        input_file=None,
        input_interface=args.interface,
        output_mode="csv",
        output=args.csv_backup,
        verbose=args.verbose,
    )

    # Replace CICFlowMeter's normal CSV writer with our DualWriter.
    session.output_writer = writer

    logger.info(
        f"Starting live capture on {args.interface} "
        f"(session_label={args.session_label!r}) -- Ctrl+C to stop"
    )

    # -----------------------------------------------------------------------
    # Start packet capture
    # -----------------------------------------------------------------------

    sniffer.start()

    # -----------------------------------------------------------------------
    # Start background garbage collector
    # -----------------------------------------------------------------------

    gc_stop = threading.Event()

    gc_thread = threading.Thread(
        target=run_gc_thread,
        args=(session, gc_stop, 10.0),
        daemon=True,
        name="flow-gc",
    )

    gc_thread.start()

    logger.info(
        "Background GC thread started "
        "(idle timeout = 15 s, interval = 10 s)"
    )

    # -----------------------------------------------------------------------
    # Main monitoring loop
    # -----------------------------------------------------------------------

    try:
        while True:
            time.sleep(10)

            stats = writer.stats()

            logger.info(
                f"published={stats['published']} "
                f"dropped={stats['dropped_from_queue']} "
                f"queue_depth={stats['queue_depth']} "
                f"flows_in_progress={len(session.flows)}"
            )

    except KeyboardInterrupt:
        logger.info("Stopping capture...")

    finally:
        # -------------------------------------------------------------------
        # Stop GC
        # -------------------------------------------------------------------

        gc_stop.set()

        gc_thread.join(timeout=3.0)

        # -------------------------------------------------------------------
        # Stop packet capture
        # -------------------------------------------------------------------

        try:
            sniffer.stop()
        except Exception:
            logger.exception(
                "Error while stopping packet sniffer"
            )

        try:
            sniffer.join()
        except Exception:
            logger.exception(
                "Error while joining packet sniffer"
            )

        # -------------------------------------------------------------------
        # Flush remaining flows
        # -------------------------------------------------------------------

        try:
            session.flush_flows()
        except Exception:
            logger.exception(
                "Error while flushing remaining flows"
            )

        # -------------------------------------------------------------------
        # Finish Redis publishing and close CSV
        # -------------------------------------------------------------------

        writer.close()

        logger.info(
            f"Final stats: {writer.stats()}"
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()