#!/usr/bin/env python3
"""PostgreSQL Database Restore Utility — Stage 11 Infrastructure.

Restores the PostgreSQL database from a backup file (.dump custom archive or .sql plain file).

Usage:
    python scripts/restore_db.py --backup-file PATH_TO_BACKUP [--clean]

Environment Variables:
    POSTGRES_HOST       Database host (default: localhost)
    POSTGRES_PORT       Database port (default: 5432)
    POSTGRES_DB         Database name (default: soc_telemetry)
    POSTGRES_USER       Database user (default: soc_user)
    POSTGRES_PASSWORD   Database password (default: none / prompts if unset)
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def run_restore(backup_file: Path, clean: bool = False) -> None:
    if not backup_file.exists():
        print(f"[-] ERROR: Backup file not found: {backup_file}", file=sys.stderr)
        sys.exit(1)

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    dbname = os.getenv("POSTGRES_DB", "soc_telemetry")
    user = os.getenv("POSTGRES_USER", "soc_user")
    password = os.getenv("POSTGRES_PASSWORD", "")

    print(f"[*] Starting PostgreSQL restore into '{dbname}' on {host}:{port}...")
    print(f"[*] Source backup file: {backup_file} ({backup_file.stat().st_size:,} bytes)")

    # Detect file type (.dump vs .sql)
    is_custom = backup_file.suffix.lower() in [".dump", ".custom", ".bin"]

    pg_restore_bin = shutil.which("pg_restore")
    psql_bin = shutil.which("psql")

    env = os.environ.copy()
    if password:
        env["PGPASSWORD"] = password

    if is_custom:
        if not pg_restore_bin:
            docker_bin = shutil.which("docker")
            if docker_bin:
                print("[*] Local pg_restore not found. Attempting containerized restore via Docker...")
                # Copy file into container
                container_path = f"/tmp/{backup_file.name}"
                cp_cmd = ["docker", "cp", str(backup_file), f"soc_telemetry_postgres:{container_path}"]
                subprocess.run(cp_cmd, check=True)
                
                clean_flags = ["--clean", "--if-exists"] if clean else []
                cmd = [
                    "docker", "exec", "soc_telemetry_postgres",
                    "pg_restore", "-U", user, "-d", dbname, *clean_flags, "-v", container_path
                ]
                res = subprocess.run(cmd, env=env, capture_output=True, text=True)
                if res.returncode != 0 and "error" in res.stderr.lower():
                    print(f"[-] ERROR: Containerized pg_restore failed: {res.stderr}", file=sys.stderr)
                    sys.exit(1)
                print("[+] Restore completed successfully via Docker.")
                return
            else:
                print("[-] ERROR: Neither 'pg_restore' nor 'docker' is available in PATH.", file=sys.stderr)
                sys.exit(1)

        clean_flags = ["--clean", "--if-exists"] if clean else []
        cmd = [
            pg_restore_bin,
            "-h", host,
            "-p", port,
            "-U", user,
            "-d", dbname,
            *clean_flags,
            "-v",
            str(backup_file),
        ]
    else:
        # Plain SQL restore via psql
        if not psql_bin:
            print("[-] ERROR: 'psql' binary is required for restoring plain .sql files.", file=sys.stderr)
            sys.exit(1)
        cmd = [
            psql_bin,
            "-h", host,
            "-p", port,
            "-U", user,
            "-d", dbname,
            "-f", str(backup_file),
        ]

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        # Note: pg_restore emits non-zero on minor warnings unless filtered, check stderr
        if result.returncode != 0 and "fatal" in result.stderr.lower():
            print(f"[-] ERROR: Restore failed with exit code {result.returncode}:\n{result.stderr}", file=sys.stderr)
            sys.exit(1)

        print("[+] PostgreSQL database restore completed successfully.")

    except Exception as e:
        print(f"[-] ERROR: Exception during restore execution: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PostgreSQL Database Restore Utility")
    parser.add_argument(
        "--backup-file",
        type=Path,
        required=True,
        help="Path to the backup file to restore (.dump or .sql)",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        default=True,
        help="Clean (drop) database objects before recreating them (default: True)",
    )
    args = parser.parse_args()
    run_restore(args.backup_file, args.clean)
