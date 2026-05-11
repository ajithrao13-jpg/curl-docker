"""
test_sql_runner.py
==================
pytest-based runner for SQL-driven test cases.

Discovers SQL testcase files, parses them using
:mod:`tests.helpers.sql_test_parser`, and generates individual pytest test
items – one per SQL test case.  The ``clean_tables`` autouse fixture
(conftest.py) resets all tables before every test case exactly as it does for
any other pytest test.

Path configuration:
  - SQL_TESTCASE_GLOB controls where testcase `.sql` files are discovered.
  - Supports one or many comma-separated glob patterns.

Examples:
  SQL_TESTCASE_GLOB="tests/sql/testcases/*.sql" pytest tests/ -v
  SQL_TESTCASE_GLOB="objects/**/testcases/**/*.sql" pytest tests/ -v

How to add a new test
---------------------
1. Create (or open) a ``*.sql`` file in ``tests/sql/testcases/``.
2. Write your test case using the ``@@TEST`` / ``@@ASSERT`` / ``@@END_TEST``
   markers (see ``tests/helpers/sql_test_parser.py`` for full format docs).
3. Run ``pytest`` – your new test is discovered automatically.
   **No Python code changes required.**

Assertion contract
------------------
Every ``@@ASSERT`` SELECT must return exactly **one row with one column**.
- Value ``1`` → assertion passes.
- Any other value (including ``0``, ``NULL``, or no rows) → assertion fails.

Failure messages include:
- The assertion description.
- The actual value returned.
- The SQL that produced it.
"""

from __future__ import annotations

import os
from glob import glob
from pathlib import Path
import textwrap

import pytest

from tests.helpers.sql_test_parser import SqlTestCase, parse_sql_test_file

# ---------------------------------------------------------------------------
# Test-case discovery (runs at collection time – no DB connection needed)
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SQL_TESTCASE_GLOB = os.environ.get("SQL_TESTCASE_GLOB", "tests/sql/testcases/*.sql")


def _discover_testcase_files(glob_value: str) -> list[Path]:
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


_ALL_CASES: list[SqlTestCase] = []
for testcase_file in _discover_testcase_files(SQL_TESTCASE_GLOB):
    _ALL_CASES.extend(parse_sql_test_file(str(testcase_file)))


# ---------------------------------------------------------------------------
# pytest parametrization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "sql_test_case",
    _ALL_CASES,
    ids=[tc.full_id for tc in _ALL_CASES],
)
def test_sql_case(db_conn, sql_test_case: SqlTestCase) -> None:
    """
    Execute a SQL-defined test case.

    Steps
    -----
    1. Run the body SQL (setup inserts + EXEC stored-procedure call).
    2. Run each ``@@ASSERT`` SELECT; collect failures.
    3. Fail with a combined message if any assertion did not return 1.
    """
    cursor = db_conn.cursor()
    try:
        _run_body(cursor, sql_test_case)
        failures = _run_assertions(cursor, sql_test_case)
    finally:
        cursor.close()

    if failures:
        count = len(failures)
        header = (
            f"Test '{sql_test_case.name}' – {count} assertion(s) failed:\n"
        )
        detail = "\n".join(
            f"  [{i + 1}] {msg}" for i, msg in enumerate(failures)
        )
        pytest.fail(header + detail, pytrace=False)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run_body(cursor, tc: SqlTestCase) -> None:
    """Execute the test body (setup + EXEC) as one or more T-SQL batches."""
    if not tc.body_sql.strip():
        return

    # Split on GO separators so multi-batch scripts are handled correctly.
    import re
    batches = re.split(r"^\s*GO\s*$", tc.body_sql, flags=re.MULTILINE | re.IGNORECASE)
    batches = [b.strip() for b in batches if b.strip()]

    for batch in batches:
        # Prepend SET NOCOUNT ON so that DML "rows affected" messages do not
        # leave unexpected result sets open on the pyodbc cursor.
        sql = "SET NOCOUNT ON;\n" + batch
        try:
            cursor.execute(sql)
            # Drain any result sets produced by nested stored procedures.
            while cursor.nextset():
                pass
        except Exception as exc:
            pytest.fail(
                f"Body SQL execution failed in '{tc.name}':\n"
                f"{textwrap.indent(batch, '  ')}\n\n"
                f"Error: {exc}",
                pytrace=False,
            )


def _run_assertions(cursor, tc: SqlTestCase) -> list[str]:
    """Run all ``@@ASSERT`` SELECTs; return a list of failure message strings."""
    failures: list[str] = []

    for idx, assertion in enumerate(tc.assertions, start=1):
        try:
            cursor.execute(assertion.sql)
            row = cursor.fetchone()
        except Exception as exc:
            failures.append(
                f"Assertion {idx} '{assertion.description}' raised an error: {exc}\n"
                f"    SQL: {assertion.sql}"
            )
            continue

        if row is None:
            failures.append(
                f"Assertion {idx} '{assertion.description}' returned no rows "
                f"(expected 1 row with value 1).\n"
                f"    SQL: {assertion.sql}"
            )
        elif row[0] != 1:
            failures.append(
                f"Assertion {idx} '{assertion.description}' FAILED "
                f"(got {row[0]!r}, expected 1).\n"
                f"    SQL: {assertion.sql}"
            )

    return failures
