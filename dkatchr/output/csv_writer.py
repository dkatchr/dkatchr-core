"""
CSV writer — small wrapper around csv.DictWriter for the result file.

EXTRACTED FROM: dkatchr/cli.py (the csv.DictWriter + locking dance).
WHY: CLI orchestration shouldn't be doing csv module bookkeeping. The
writer here is a thread-safe convenience for the runner.
"""

import csv
import threading
from contextlib import contextmanager
from typing import Iterator

from dkatchr.output.schema import RESULT_FIELDS


class CsvResultWriter:
    """Thread-safe wrapper around csv.DictWriter for streaming scan rows."""

    def __init__(self, fh) -> None:
        self._writer = csv.DictWriter(fh, fieldnames=RESULT_FIELDS)
        self._lock   = threading.Lock()
        self._writer.writeheader()

    def write_rows(self, rows: list[dict]) -> int:
        if not rows:
            return 0
        with self._lock:
            self._writer.writerows(rows)
        return len(rows)


@contextmanager
def open_csv_writer(path: str) -> Iterator[CsvResultWriter]:
    """`with open_csv_writer('out.csv') as w: w.write_rows(...)`"""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        yield CsvResultWriter(fh)
