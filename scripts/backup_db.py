#!/usr/bin/env python3
"""PostgreSQL Database Backup Utility — Stage 11 Infrastructure.

Dumps the PostgreSQL database to a compressed custom archive (-F c) or plain SQL format.

Usage:
    python scripts/backup_db.py [--output-dir BACKUP_DIR] [--format custom|plain]

Environment Variables:
    POSTGRES_HOST       Database host (default: localhost)
    POSTGRES_PORT       Database port (default: 5432)
    POSTGRES_DB         Database name (default: soc_telemetry)
    POSTGRES_USER       Database user (default: soc_user)
    POSTGRES_PASSWORD   Database password (default: none / prompts if unset)
"""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_backup(output_dir: Path, backup_format: str = "custom") -> Path:
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    dbname = os.getenv("POSTGRES_DB", "soc_telemetry")
    user = os.getenv("POSTGRES_USER", "soc_user")
    password = os.getenv("POSTGRES_PASSWORD", "")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    ext = "dump" if backup_format == "custom" else "sql"
    filename = f"{dbname}_backup_{timestamp}.{ext}"
    output_path = output_dir / filename

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Starting PostgreSQL backup for '{dbname}' on {host}:{port}...")
    print(f"[*] Target backup file: {output_path}")

    # Check for pg_dump
    pg_dump_bin = shutil.which("pg_dump")
    if not pg_dump_bin:
        # Check if docker is available to run containerized pg_dump
        docker_bin = shutil.which("docker")
        if docker_bin:
            print("[*] Local pg_dump not found. Attempting containerized backup via Docker...")
            format_flag = "-Fc" if backup_format == "custom" else "-Fp"
            cmd = [
                "docker", "exec", "soc_telemetry_postgres",
                "pg_dump", "-U", user, "-d", dbname, format_flag, "-f", f"/tmp/{filename}"
            ]
            env = os.environ.copy()
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            if res.returncode != 0:
                print(f"[-] ERROR: Containerized pg_dump failed: {res.stderr}", file=sys.stderr)
                sys.exit(1)
            # Copy out
            cp_cmd = ["docker", "cp", f"soc_telemetry_postgres:/tmp/{filename}", str(output_path)]
            subprocess.run(cp_cmd, check=True)
            print(f"[+] Backup successfully generated via Docker: {output_path} ({output_path.stat().st_size:,} bytes)")
            return output_path
        else:
            print("[-] ERROR: Neither 'pg_dump' nor 'docker' is available in PATH.", file=sys.stderr)
            sys.exit(1)

    format_flag = "-Fc" if backup_format == "custom" else "-Fp"
    cmd = [
        pg_dump_bin,
        "-h", host,
        "-p", port,
        "-U", user,
        "-d", dbname,
        format_flag,
        "-f", str(output_path),
    ]

    env = os.environ.copy()
    if password:
        env["PGPASSWORD"] = password

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] ERROR: pg_dump failed with exit code {result.returncode}:\n{result.stderr}", file=sys.stderr)
            sys.exit(1)

        if not output_path.exists() or output_path.stat().st_size == 0:
            print("[-] ERROR: Backup file was not created or is empty.", file=sys.stderr)
            sys.exit(1)

        size_bytes = output_path.stat().st_size
        print(f"[+] Backup completed successfully: {output_path} ({size_bytes:,} bytes)")
        return output_path

    except Exception as e:
        print(f"[-] ERROR: Exception during pg_dump execution: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PostgreSQL Database Backup Utility")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "backups",
        help="Directory to save the backup file (default: ./backups)",
    )
    parser.add_argument(
        "--format",
        choices=["custom", "plain"],
        default="custom",
        help="Backup format: 'custom' (.dump for pg_restore) or 'plain' (.sql)",
    )
    args = parser.parse_args()
    run_backup(args.output_dir, args.format)
