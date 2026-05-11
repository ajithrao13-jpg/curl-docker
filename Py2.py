"""
setup_db.py – Bootstrap script executed once before the test suite.

Responsibilities:
  1. Wait for SQL Server to become available.
  2. Create the test database if it does not already exist.
  3. Execute DDL scripts (tables → stored procedures) inside the test DB.

Usage:
    python tests/setup_db.py

Path configuration (new-contributor friendly):
  - SQL_DDL_GLOB controls where setup DDL `.sql` files are loaded from.
  - It accepts one or many comma-separated glob patterns.
  - Patterns can be relative to repo root or absolute paths.

Examples:
    SQL_DDL_GLOB="tests/sql/*.sql" python tests/setup_db.py
    SQL_DDL_GLOB="objects/**/*.sql" python tests/setup_db.py
    SQL_DDL_GLOB="objects/**/*.sql,liquibase/sql/**/*.sql" python tests/setup_db.py
"""

from __future__ import annotations

import os
import re
import sys
import time
from glob import glob
from pathlib import Path

import pyodbc

# ---------------------------------------------------------------------------
# Configuration (all values overridable via environment variables)
# ---------------------------------------------------------------------------
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "1433")
DB_NAME = os.environ.get("DB_NAME", "TestDB")
DB_USER = os.environ.get("DB_USER", "sa")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "Str0ngPass!2024")

MASTER_CONN_STR = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={DB_HOST},{DB_PORT};"
    "DATABASE=master;"
    f"UID={DB_USER};"
    f"PWD={DB_PASSWORD};"
    "TrustServerCertificate=yes;"
)

TEST_CONN_STR = (
    f"DRIVER={{ODBC Driver 18 for SQL Server}};"
    f"SERVER={DB_HOST},{DB_PORT};"
    f"DATABASE={DB_NAME};"
    f"UID={DB_USER};"
    f"PWD={DB_PASSWORD};"
    "TrustServerCertificate=yes;"
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SQL_DDL_GLOB = os.environ.get("SQL_DDL_GLOB", "tests/sql/*.sql")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def split_go_batches(sql: str) -> list[str]:
    """Split a T-SQL script on GO batch separators."""
    batches = re.split(r"^\s*GO\s*$", sql, flags=re.MULTILINE | re.IGNORECASE)
    return [b.strip() for b in batches if b.strip()]


def execute_sql_file(cursor, filepath: str) -> None:
    """Read *filepath*, split on GO, and execute each batch."""
    with open(filepath, encoding="utf-8") as fh:
        sql = fh.read()
    for batch in split_go_batches(sql):
        cursor.execute(batch)


def _discover_sql_files(glob_value: str) -> list[Path]:
    """
    Resolve SQL files from one or many glob patterns.

    Supported:
      - file patterns (e.g. tests/sql/*.sql, objects/**/*.sql)
      - directory patterns (e.g. objects/**/) where all nested *.sql are loaded
    """
    files: set[Path] = set()

    patterns = [p.strip() for p in glob_value.split(",") if p.strip()]
    for pattern in patterns:
        raw_pattern = pattern
        if not os.path.isabs(pattern):
            raw_pattern = str(PROJECT_ROOT / pattern)

        matches = [Path(match) for match in glob(raw_pattern, recursive=True)]
        for match in matches:
            if match.is_file() and match.suffix.lower() == ".sql":
                files.add(match.resolve())
            elif match.is_dir():
                files.update(
                    candidate.resolve()
                    for candidate in match.rglob("*.sql")
                    if candidate.is_file()
                )

    return sorted(files, key=lambda p: str(p).lower())


def wait_for_sql_server(retries: int = 30, delay: int = 5) -> bool:
    """Poll SQL Server until it accepts a connection or retries are exhausted."""
    print(f"Waiting for SQL Server at {DB_HOST}:{DB_PORT} ...")
    for attempt in range(1, retries + 1):
        try:
            conn = pyodbc.connect(MASTER_CONN_STR, timeout=5, autocommit=True)
            conn.close()
            print(f"  SQL Server is ready (attempt {attempt}).")
            return True
        except Exception as exc:
            print(f"  Attempt {attempt}/{retries} failed: {exc}")
            time.sleep(delay)
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def setup() -> None:
    if not wait_for_sql_server():
        print("ERROR: SQL Server did not become available in time.", file=sys.stderr)
        sys.exit(1)

    # Create the test database
    conn = pyodbc.connect(MASTER_CONN_STR, autocommit=True)
    cursor = conn.cursor()
    cursor.execute(
        f"IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = N'{DB_NAME}')"
        f"    CREATE DATABASE [{DB_NAME}];"
    )
    conn.close()
    print(f"Database '{DB_NAME}' is ready.")

    # Execute DDL scripts in deterministic sorted order.
    ddl_files = _discover_sql_files(SQL_DDL_GLOB)
    if not ddl_files:
        print(
            "ERROR: No SQL files found. "
            "Set SQL_DDL_GLOB correctly (e.g. tests/sql/*.sql or objects/**/*.sql).",
            file=sys.stderr,
        )
        sys.exit(1)

    conn = pyodbc.connect(TEST_CONN_STR, autocommit=True)
    cursor = conn.cursor()
    for filepath in ddl_files:
        print(f"Executing {filepath} ...")
        execute_sql_file(cursor, str(filepath))
    conn.close()

    print("Database setup complete.")


if __name__ == "__main__":
    setup()
