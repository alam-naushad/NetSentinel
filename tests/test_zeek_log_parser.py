import sys
import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.services.zeek.zeek_log_parser import ZeekLogParser
from app.services.zeek.zeek_connection_record import ZeekConnectionRecord

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "zeek"

class TestZeekLogParser(unittest.TestCase):
    def setUp(self):
        self.sample_json = FIXTURES_DIR / "sample_conn.json"
        self.sample_tsv = FIXTURES_DIR / "sample_conn.tsv"
        self.malformed_log = FIXTURES_DIR / "malformed_conn.log"

    def test_parse_valid_json_log(self):
        with open(self.sample_json, "rb") as f:
            content = f.read()

        result = ZeekLogParser.parse_file(content)
        self.assertEqual(result.format_detected, "json")
        self.assertEqual(result.malformed_count, 0)
        self.assertEqual(result.duplicate_count, 0)
        self.assertEqual(len(result.connections), 15)

        first_conn = result.connections[0]
        self.assertIsInstance(first_conn, ZeekConnectionRecord)
        self.assertTrue(hasattr(first_conn, "uid"))
        self.assertTrue(hasattr(first_conn, "id_orig_h"))
        self.assertTrue(hasattr(first_conn, "id_orig_p"))
        self.assertTrue(hasattr(first_conn, "id_resp_h"))
        self.assertTrue(hasattr(first_conn, "id_resp_p"))
        self.assertTrue(hasattr(first_conn, "proto"))
        self.assertTrue(hasattr(first_conn, "service"))
        self.assertTrue(hasattr(first_conn, "duration"))
        self.assertTrue(hasattr(first_conn, "orig_bytes"))

    def test_parse_valid_tsv_log(self):
        with open(self.sample_tsv, "rb") as f:
            content = f.read()

        result = ZeekLogParser.parse_file(content)
        self.assertEqual(result.format_detected, "tsv")
        self.assertEqual(result.malformed_count, 0)
        self.assertEqual(result.duplicate_count, 0)
        self.assertEqual(len(result.connections), 15)

    def test_format_autodetection(self):
        result1 = ZeekLogParser.parse_file(b'{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n')
        self.assertEqual(result1.format_detected, "json")

        result2 = ZeekLogParser.parse_file(b'#separator \\x09\n#fields\\tts\\tuid\\n1.0\\t1\\n')
        self.assertEqual(result2.format_detected, "tsv")

        leading_empty_content = b'\n\n{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n'
        result3 = ZeekLogParser.parse_file(leading_empty_content)
        self.assertEqual(result3.format_detected, "json")

    def test_malformed_records_handling(self):
        with open(self.malformed_log, "rb") as f:
            content = f.read()

        result = ZeekLogParser.parse_file(content)
        self.assertGreater(result.malformed_count, 0)
        self.assertGreater(len(result.connections), 0)

    def test_batch_uid_deduplication(self):
        content = b'{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n{"ts": 2.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n'
        result = ZeekLogParser.parse_file(content)
        self.assertEqual(len(result.connections), 1)
        self.assertEqual(result.duplicate_count, 1)

    def test_max_connections_limit(self):
        content = b'{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n{"ts": 2.0, "uid": "2", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp"}\n'
        result = ZeekLogParser.parse_file(content, max_connections=1)
        self.assertEqual(len(result.connections), 1)

    def test_empty_file_handling(self):
        result = ZeekLogParser.parse_file(b"")
        self.assertEqual(len(result.connections), 0)
        self.assertEqual(result.total_lines_read, 0)
        self.assertEqual(result.format_detected, "unknown")

    def test_missing_optional_fields(self):
        content = b'{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp", "duration": "-", "service": "-", "orig_bytes": "-", "history": "-"}\n'
        result = ZeekLogParser.parse_file(content)
        self.assertGreater(len(result.connections), 0)
        conn = result.connections[0]
        self.assertIsNone(conn.duration)
        self.assertIsNone(conn.service)
        self.assertIsNone(conn.orig_bytes)
        self.assertIsNone(conn.history)

    def test_tunnel_parents_normalization(self):
        c1 = b'{"ts": 1.0, "uid": "1", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp", "tunnel_parents": ["a", "b"]}\n'
        c2 = b'{"ts": 2.0, "uid": "2", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp", "tunnel_parents": []}\n'
        c3 = b'{"ts": 3.0, "uid": "3", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp", "tunnel_parents": "a"}\n'
        c4 = b'{"ts": 4.0, "uid": "4", "id.orig_h": "1.1.1.1", "id.orig_p": 1, "id.resp_h": "2.2.2.2", "id.resp_p": 2, "proto": "tcp", "tunnel_parents": "-"}\n'

        res = ZeekLogParser.parse_file(c1 + c2 + c3 + c4)
        
        self.assertEqual(len(res.connections), 4)
        self.assertEqual(res.connections[0].tunnel_parents, "a,b")
        self.assertIsNone(res.connections[1].tunnel_parents)
        self.assertEqual(res.connections[2].tunnel_parents, "a")
        self.assertIsNone(res.connections[3].tunnel_parents)

if __name__ == "__main__":
    unittest.main()
