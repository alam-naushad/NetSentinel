"""Zeek Spool Directory Tailer.

Monitors a whitelisted spool directory for Zeek ``conn*.log`` files, reads
new data from the last confirmed offset, parses connection records, and
enqueues them to a bounded ``asyncio.Queue`` for downstream processing.

Security:
    - Only the configured ``ZEEK_SPOOL_DIR`` is accessed.
    - All resolved paths are validated to be within the spool directory.
    - Maximum line length prevents memory exhaustion from malicious input.
"""

from __future__ import annotations

import asyncio
import logging
import os
import fnmatch
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.services.zeek.zeek_connection_record import ZeekConnectionRecord
from app.services.zeek.zeek_log_parser import ZeekLogParser

logger = logging.getLogger(__name__)

MAX_LINE_LENGTH = 65536  # 64 KB


class FileState:
    """Tracks per-file tailing state."""

    __slots__ = (
        "path", "file_name", "byte_offset", "lines_read",
        "inode", "headers", "format_detected",
    )

    def __init__(
        self,
        path: Path,
        byte_offset: int = 0,
        lines_read: int = 0,
        inode: int | None = None,
    ):
        self.path = path
        self.file_name = path.name
        self.byte_offset = byte_offset
        self.lines_read = lines_read
        self.inode = inode
        self.headers: List[str] | None = None
        self.format_detected: str | None = None  # 'json' or 'tsv'


class TailerCounters:
    """Observable counters for the tailer."""

    def __init__(self):
        self.records_read: int = 0
        self.records_parsed: int = 0
        self.records_malformed: int = 0
        self.records_enqueued: int = 0


class SpoolTailer:
    """Tails Zeek log files in a whitelisted spool directory."""

    def __init__(
        self,
        spool_dir: str,
        queue: asyncio.Queue,
        *,
        file_pattern: str = "conn*.log",
        poll_interval_sec: float = 1.0,
        initial_offsets: Dict[str, int] | None = None,
    ):
        self._spool_dir = Path(spool_dir).resolve()
        self._queue = queue
        self._file_pattern = file_pattern
        self._poll_interval = poll_interval_sec
        self._initial_offsets = initial_offsets or {}

        self._file_states: Dict[str, FileState] = {}
        self._stop_event = asyncio.Event()
        self._paused = asyncio.Event()
        self._paused.set()  # initially not paused (set = running)
        self.counters = TailerCounters()

        # Validate spool directory
        if not self._spool_dir.is_absolute():
            raise ValueError(f"Spool directory must be absolute: {spool_dir}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Main run loop: discover files, tail new data, enqueue records."""
        logger.info(
            "SpoolTailer starting: dir=%s, pattern=%s, poll=%.1fs",
            self._spool_dir,
            self._file_pattern,
            self._poll_interval,
        )
        try:
            while not self._stop_event.is_set():
                # Honour pause (e.g. DB unavailable)
                await self._paused.wait()
                if self._stop_event.is_set():
                    break

                await self._scan_and_tail()
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self._poll_interval,
                    )
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            logger.info("SpoolTailer cancelled.")
        except Exception:
            logger.exception("SpoolTailer unexpected error")
        finally:
            logger.info(
                "SpoolTailer stopped. read=%d parsed=%d malformed=%d enqueued=%d",
                self.counters.records_read,
                self.counters.records_parsed,
                self.counters.records_malformed,
                self.counters.records_enqueued,
            )

    def request_stop(self) -> None:
        """Signal the tailer to stop after the current iteration."""
        self._stop_event.set()
        self._paused.set()  # unblock if paused

    def pause(self) -> None:
        """Pause file reading (e.g. when DB is unavailable)."""
        self._paused.clear()
        logger.warning("SpoolTailer paused.")

    def resume(self) -> None:
        """Resume file reading."""
        self._paused.set()
        logger.info("SpoolTailer resumed.")

    @property
    def is_running(self) -> bool:
        return not self._stop_event.is_set()

    # ------------------------------------------------------------------
    # Internal: scan and tail
    # ------------------------------------------------------------------

    async def _scan_and_tail(self) -> None:
        """Discover matching log files and read new data."""
        if not self._spool_dir.is_dir():
            return

        # Discover matching files
        try:
            entries = list(self._spool_dir.iterdir())
        except PermissionError:
            logger.error("Permission denied reading spool dir: %s", self._spool_dir)
            return

        for entry in sorted(entries):
            if self._stop_event.is_set():
                break
            if not entry.is_file():
                continue
            if not fnmatch.fnmatch(entry.name, self._file_pattern):
                continue
            # Security: verify path is within spool dir
            try:
                resolved = entry.resolve()
                resolved.relative_to(self._spool_dir)
            except (ValueError, OSError):
                logger.warning("Skipping file outside spool dir: %s", entry)
                continue

            await self._tail_file(resolved)

    async def _tail_file(self, path: Path) -> None:
        """Read new data from a single log file."""
        name = path.name
        try:
            stat = path.stat()
        except FileNotFoundError:
            # File disappeared between scan and tail
            self._file_states.pop(name, None)
            return

        current_inode = getattr(stat, "st_ino", 0)
        current_size = stat.st_size

        state = self._file_states.get(name)

        if state is None:
            # New file — check for recovered offset
            initial_offset = self._initial_offsets.get(name, 0)
            state = FileState(
                path=path,
                byte_offset=min(initial_offset, current_size),
                inode=current_inode,
            )
            self._file_states[name] = state
            logger.info(
                "Tracking new file: %s (offset=%d, size=%d)",
                name, state.byte_offset, current_size,
            )

        # Detect rotation: inode changed or file shrank
        if state.inode and current_inode and current_inode != state.inode:
            logger.info("Rotation detected (inode change) for %s", name)
            state.byte_offset = 0
            state.inode = current_inode
            state.headers = None
            state.format_detected = None
        elif current_size < state.byte_offset:
            logger.info("Rotation detected (size shrink) for %s", name)
            state.byte_offset = 0
            state.headers = None
            state.format_detected = None
            state.inode = current_inode

        # Nothing new to read
        if current_size <= state.byte_offset:
            return

        # Read new data
        records, new_offset = await asyncio.to_thread(
            self._read_new_lines, state, current_size
        )

        # Enqueue parsed records with exact per-line byte offsets
        for rec_data, line_offset in records:
            if self._stop_event.is_set():
                break
            tagged = {
                "_file_name": name,
                "_byte_offset": line_offset,
                "_record": rec_data,
            }
            try:
                await asyncio.wait_for(
                    self._queue.put(tagged),
                    timeout=5.0,
                )
                self.counters.records_enqueued += 1
            except asyncio.TimeoutError:
                logger.warning(
                    "Queue full (backpressure) — tailer pausing for file %s", name,
                )
                # Don't advance offset past what we successfully enqueued
                return

        # Update in-memory state (durable offset updated by IngestionWorker)
        state.byte_offset = new_offset

    def _read_new_lines(
        self, state: FileState, max_pos: int
    ) -> tuple[list[tuple[ZeekConnectionRecord, int]], int]:
        """Synchronous file read — runs in a thread.

        Returns (list_of_(record, line_end_offset), new_byte_offset).
        """
        records: list[tuple[ZeekConnectionRecord, int]] = []
        offset = state.byte_offset

        try:
            with open(state.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                while True:
                    line_start = f.tell()
                    if line_start >= max_pos:
                        break
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        # Partial line — don't consume it
                        break

                    self.counters.records_read += 1
                    offset = f.tell()

                    stripped = line.strip()
                    if not stripped:
                        continue
                    if len(stripped) > MAX_LINE_LENGTH:
                        self.counters.records_malformed += 1
                        continue

                    # Skip Zeek header/comment lines
                    if stripped.startswith("#"):
                        # Capture TSV headers
                        if stripped.startswith("#fields"):
                            state.headers = stripped.split("\t")[1:]
                            state.format_detected = "tsv"
                        continue

                    # Parse the line
                    rec = self._parse_line(stripped, state)
                    if rec is not None:
                        records.append((rec, offset))
                        self.counters.records_parsed += 1
                    else:
                        self.counters.records_malformed += 1

        except Exception:
            logger.exception("Error reading %s", state.path)

        return records, offset

    def _parse_line(
        self, line: str, state: FileState
    ) -> ZeekConnectionRecord | None:
        """Parse a single line as JSON or TSV."""
        try:
            # Auto-detect format
            if state.format_detected is None:
                if line.startswith("{"):
                    state.format_detected = "json"
                elif state.headers:
                    state.format_detected = "tsv"
                else:
                    # Try JSON
                    state.format_detected = "json"

            parsed: Dict[str, Any] | None = None
            if state.format_detected == "json":
                parsed = ZeekLogParser._parse_json_line(line)
            elif state.format_detected == "tsv" and state.headers:
                parsed = ZeekLogParser._parse_tsv_line(line, state.headers)

            if parsed is None:
                return None

            return ZeekConnectionRecord.model_validate(parsed)
        except Exception:
            return None
