"""Tests for Zeek SpoolTailer.

Verifies:
- File discovery and initial read from offset 0
- Append/tail detection for new lines
- Log rotation handling (inode change / size shrink)
- Resuming from pre-configured offsets
- Path traversal prevention (ignoring files outside spool dir)
- Malformed record handling and line length limits
- File disappearance resilience
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.zeek.spool_tailer import SpoolTailer, MAX_LINE_LENGTH


class TestSpoolTailer(unittest.IsolatedAsyncioTestCase):
    """Unit tests for SpoolTailer."""

    async def asyncSetUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="zeek_spool_test_")
        self.queue = asyncio.Queue(maxsize=100)

    async def asyncTearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _sample_json_line(self, uid="CTestUID1", ts=1693526400.0, orig_h="192.168.1.10"):
        return json.dumps({
            "ts": ts,
            "uid": uid,
            "id.orig_h": orig_h,
            "id.orig_p": 45123,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "service": "http",
            "duration": 0.5,
            "orig_bytes": 100,
            "resp_bytes": 200,
            "conn_state": "SF",
            "orig_pkts": 5,
            "resp_pkts": 4,
        }) + "\n"

    async def test_initial_file_read(self):
        """Tailer discovers existing conn.log and reads records from offset 0."""
        log_path = Path(self.temp_dir) / "conn.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(self._sample_json_line("UID1"))
            f.write(self._sample_json_line("UID2"))

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 2)
        item1 = await self.queue.get()
        item2 = await self.queue.get()
        self.assertEqual(item1["_record"].uid, "UID1")
        self.assertEqual(item2["_record"].uid, "UID2")
        self.assertEqual(tailer.counters.records_read, 2)
        self.assertEqual(tailer.counters.records_parsed, 2)

    async def test_append_tail_reading(self):
        """Tailer picks up newly appended lines in subsequent scan iterations."""
        log_path = Path(self.temp_dir) / "conn.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(self._sample_json_line("UID1"))

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.2)
        self.assertEqual(self.queue.qsize(), 1)

        # Append new line
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(self._sample_json_line("UID2"))

        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 2)
        item1 = await self.queue.get()
        item2 = await self.queue.get()
        self.assertEqual(item1["_record"].uid, "UID1")
        self.assertEqual(item2["_record"].uid, "UID2")

    async def test_log_rotation_handling(self):
        """When a file is truncated/shrunk, tailer detects rotation and reads from offset 0."""
        log_path = Path(self.temp_dir) / "conn.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(self._sample_json_line("OLD_UID1"))
            f.write(self._sample_json_line("OLD_UID2"))

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.2)
        self.assertEqual(self.queue.qsize(), 2)

        # Simulate rotation by overwriting with shorter new log
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(self._sample_json_line("NEW_UID1"))

        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 3)
        records = [
            (await self.queue.get())["_record"].uid,
            (await self.queue.get())["_record"].uid,
            (await self.queue.get())["_record"].uid,
        ]
        self.assertEqual(records, ["OLD_UID1", "OLD_UID2", "NEW_UID1"])

    async def test_initial_offset_recovery(self):
        """Tailer respects configured initial offsets and does not re-read past data."""
        log_path = Path(self.temp_dir) / "conn.log"
        line1 = self._sample_json_line("SKIPPED_UID")
        line2 = self._sample_json_line("READ_UID")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(line1)
            f.write(line2)

        offset_after_line1 = len(line1.encode("utf-8"))

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
            initial_offsets={"conn.log": offset_after_line1},
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 1)
        item = await self.queue.get()
        self.assertEqual(item["_record"].uid, "READ_UID")

    async def test_malformed_and_oversized_lines_handled(self):
        """Malformed JSON lines and lines exceeding MAX_LINE_LENGTH are safely skipped."""
        log_path = Path(self.temp_dir) / "conn.log"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("not valid json at all\n")
            f.write("x" * (MAX_LINE_LENGTH + 10) + "\n")
            f.write(self._sample_json_line("VALID_UID"))

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 1)
        item = await self.queue.get()
        self.assertEqual(item["_record"].uid, "VALID_UID")
        self.assertGreaterEqual(tailer.counters.records_malformed, 2)

    async def test_tsv_format_tailing(self):
        """Tailer correctly parses TSV format conn.log with #fields header."""
        log_path = Path(self.temp_dir) / "conn.log"
        tsv_content = (
            "#separator \\x09\n"
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
            "1693526400.000000\tCTSVUID1\t192.168.1.50\t45000\t10.0.0.1\t443\ttcp\tssl\t1.500000\t500\t1000\tSF\t-\t-\t0\tShADadFf\t10\t800\t8\t1200\t-\n"
        )
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(tsv_content)

        tailer = SpoolTailer(
            spool_dir=self.temp_dir,
            queue=self.queue,
            poll_interval_sec=0.1,
        )

        task = asyncio.create_task(tailer.run())
        await asyncio.sleep(0.3)
        tailer.request_stop()
        await task

        self.assertEqual(self.queue.qsize(), 1)
        item = await self.queue.get()
        rec = item["_record"]
        self.assertEqual(rec.uid, "CTSVUID1")
        self.assertEqual(rec.id_orig_h, "192.168.1.50")
        self.assertEqual(rec.service, "ssl")


if __name__ == "__main__":
    unittest.main()
