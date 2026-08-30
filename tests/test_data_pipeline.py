import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))

from data_pipeline import (
    CANONICAL_COLUMNS,
    canonical_headers,
    canonicalise_row,
    map_attack_family,
    parse_number,
    process_csv,
)


class DataPipelineTests(unittest.TestCase):
    def test_all_15_cicids_raw_labels_preserve_taxonomy(self) -> None:
        """Verify all 15 raw CICIDS2017 labels are mapped to correct families and binary targets."""
        cases = [
            ("BENIGN", "BENIGN", 0),
            ("DoS Hulk", "DOS", 1),
            ("DoS GoldenEye", "DOS", 1),
            ("DoS slowloris", "DOS", 1),
            ("DoS Slowhttptest", "DOS", 1),
            ("DDoS", "DDOS", 1),
            ("PortScan", "PORT_SCAN", 1),
            ("FTP-Patator", "BRUTE_FORCE", 1),
            ("SSH-Patator", "BRUTE_FORCE", 1),
            ("Bot", "BOTNET", 1),
            ("Web Attack – Brute Force", "WEB_ATTACK", 1),
            ("Web Attack – XSS", "WEB_ATTACK", 1),
            ("Web Attack – Sql Injection", "WEB_ATTACK", 1),
            ("Infiltration", "INFILTRATION", 1),
            ("Heartbleed", "HEARTBLEED", 1),
        ]
        for raw_label, expected_family, expected_is_attack in cases:
            family, is_attack = map_attack_family(raw_label)
            self.assertEqual(family, expected_family, f"Failed family for {raw_label}")
            self.assertEqual(is_attack, expected_is_attack, f"Failed is_attack for {raw_label}")

    def test_dos_and_ddos_remain_distinct_attack_families(self) -> None:
        """Explicit check that DoS and DDoS are NOT merged into a shared category."""
        dos_family, _ = map_attack_family("DoS Hulk")
        ddos_family, _ = map_attack_family("DDoS")
        self.assertEqual(dos_family, "DOS")
        self.assertEqual(ddos_family, "DDOS")
        self.assertNotEqual(dos_family, ddos_family)

    def test_encoding_resilience_for_cp1252_en_dash_and_replacement_char(self) -> None:
        """Verify labels with Windows-1252 byte 0x96, Unicode en-dash, and replacement chars work."""
        labels = [
            "Web Attack  Brute Force",
            "Web Attack � Brute Force",
            "Web Attack – Brute Force",
            "Web Attack - Brute Force",
        ]
        for lbl in labels:
            family, is_attack = map_attack_family(lbl)
            self.assertEqual(family, "WEB_ATTACK")
            self.assertEqual(is_attack, 1)

    def test_duplicate_header_tolerance(self) -> None:
        """Ensure raw CSVs with duplicate headers (e.g. Fwd Header Length) do not crash mapping."""
        fieldnames = [
            " Destination Port",
            " Flow Duration",
            " Total Fwd Packets",
            " Total Backward Packets",
            "Total Length of Fwd Packets",
            " Total Length of Bwd Packets",
            " Flow Packets/s",
            " Fwd Header Length",
            " Fwd Header Length",
            " Label",
        ]
        resolved = canonical_headers(fieldnames)
        self.assertIn("destination_port", resolved)
        self.assertIn("flow_duration_ms", resolved)
        self.assertIn("raw_label", resolved)

    def test_parse_number_rejections(self) -> None:
        """Test rejection of non-finite, negative, missing, or invalid numeric inputs."""
        with self.assertRaisesRegex(ValueError, "NaN value"):
            parse_number("flow_duration_ms", "NaN")
        with self.assertRaisesRegex(ValueError, "infinite value"):
            parse_number("flow_packets_per_sec", "Infinity")
        with self.assertRaisesRegex(ValueError, "infinite value"):
            parse_number("flow_packets_per_sec", "-Infinity")
        with self.assertRaisesRegex(ValueError, "negative value"):
            parse_number("flow_duration_ms", "-100")
        with self.assertRaisesRegex(ValueError, "empty value"):
            parse_number("destination_port", "   ")
        with self.assertRaisesRegex(ValueError, "missing value"):
            parse_number("destination_port", None)
        with self.assertRaisesRegex(ValueError, "not numeric"):
            parse_number("flow_duration_ms", "abc")

    def test_port_validation_boundary(self) -> None:
        """Test destination port range enforcement (0 to 65535)."""
        headers = canonical_headers([
            " Destination Port", " Flow Duration", " Total Fwd Packets",
            " Total Backward Packets", "Total Length of Fwd Packets",
            " Total Length of Bwd Packets", " Flow Packets/s", " Label",
        ])
        valid_row = {
            " Destination Port": "443", " Flow Duration": "100", " Total Fwd Packets": "2",
            " Total Backward Packets": "2", "Total Length of Fwd Packets": "100",
            " Total Length of Bwd Packets": "100", " Flow Packets/s": "40.0", " Label": "BENIGN",
        }
        res = canonicalise_row(valid_row, headers)
        self.assertEqual(res["destination_port"], 443)
        self.assertEqual(res["raw_label"], "BENIGN")
        self.assertEqual(res["attack_family"], "BENIGN")
        self.assertEqual(res["is_attack"], 0)

        invalid_row = dict(valid_row, **{" Destination Port": "70000"})
        with self.assertRaisesRegex(ValueError, "outside valid port range"):
            canonicalise_row(invalid_row, headers)

    def test_process_sample_csv_end_to_end(self) -> None:
        """Test end-to-end batch processing on the updated cicids_tiny sample."""
        project_root = Path(__file__).resolve().parents[1]
        source = project_root / "data" / "samples" / "cicids_tiny.csv"
        with tempfile.TemporaryDirectory() as temporary_directory:
            destination = Path(temporary_directory) / "canonical.csv"
            report = process_csv(source, destination)

            # Sample has 10 rows: 6 valid, 4 invalid (port 99999, NaN, Infinity, -50)
            self.assertEqual(report.total_rows, 10)
            self.assertEqual(report.accepted_rows, 6)
            self.assertEqual(report.rejected_rows, 4)
            self.assertEqual(report.schema_version, "0.2.0")

            with destination.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

            self.assertEqual(len(rows), 6)
            self.assertEqual(tuple(rows[0].keys()), CANONICAL_COLUMNS)

            self.assertEqual(rows[0]["raw_label"], "BENIGN")
            self.assertEqual(rows[0]["attack_family"], "BENIGN")
            self.assertEqual(rows[0]["is_attack"], "0")

            self.assertEqual(rows[1]["raw_label"], "SSH-Patator")
            self.assertEqual(rows[1]["attack_family"], "BRUTE_FORCE")
            self.assertEqual(rows[1]["is_attack"], "1")

            self.assertEqual(rows[2]["raw_label"], "DoS Hulk")
            self.assertEqual(rows[2]["attack_family"], "DOS")
            self.assertEqual(rows[2]["is_attack"], "1")

            self.assertEqual(rows[3]["raw_label"], "PortScan")
            self.assertEqual(rows[3]["attack_family"], "PORT_SCAN")
            self.assertEqual(rows[3]["is_attack"], "1")

            self.assertEqual(rows[4]["raw_label"], "DDoS")
            self.assertEqual(rows[4]["attack_family"], "DDOS")
            self.assertEqual(rows[4]["is_attack"], "1")

            # Check that raw_label is preserved verbatim
            self.assertIn("Web Attack", rows[5]["raw_label"])
            self.assertEqual(rows[5]["attack_family"], "WEB_ATTACK")
            self.assertEqual(rows[5]["is_attack"], "1")


if __name__ == "__main__":
    unittest.main()
