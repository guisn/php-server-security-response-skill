#!/usr/bin/env python3
"""Summarize selected PHP-related log indicators without printing log contents."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import re
import sys
from pathlib import Path


PATTERNS = {
    "memory_exhaustion": re.compile(
        rb"(?:allowed memory size[^\r\n]{0,250}exhausted|out of memory|outofmemoryerror)", re.IGNORECASE
    ),
    "fatal_or_uncaught_error": re.compile(
        rb"(?:php\s+(?:fatal|parse)\s+error|fatal error:|uncaught (?:error|exception))", re.IGNORECASE
    ),
    "execution_or_request_timeout": re.compile(
        rb"(?:maximum execution time[^\r\n]{0,150}exceeded|execution timed out|request timed out|upstream timed out)",
        re.IGNORECASE,
    ),
}
ISO_TIMESTAMP = re.compile(
    rb"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
)
APACHE_TIMESTAMP = re.compile(
    rb"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) ([+-]\d{4})\]"
)
MAX_LINE_BYTES = 1024 * 1024


def parse_timestamp(line: bytes) -> dt.datetime | None:
    match = ISO_TIMESTAMP.search(line)
    if match:
        value = match.group(1).decode("ascii").replace("Z", "+00:00")
        if len(value) >= 5 and value[-5] in "+-" and value[-3] != ":":
            value = value[:-2] + ":" + value[-2:]
        try:
            parsed = dt.datetime.fromisoformat(value)
            return parsed.astimezone(dt.timezone.utc) if parsed.tzinfo else None
        except ValueError:
            return None

    match = APACHE_TIMESTAMP.search(line)
    if match:
        raw = match.group(1).decode("ascii") + " " + match.group(2).decode("ascii")
        try:
            return dt.datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(dt.timezone.utc)
        except ValueError:
            return None
    return None


def parse_after(value: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--after must include a timezone, such as 2026-10-21T14:00:00Z")
    return parsed.astimezone(dt.timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Count selected PHP error indicators in explicit logs; matched lines and secrets are never printed."
    )
    parser.add_argument("--after", help="Optional timezone-aware ISO-8601 lower bound; Apache and ISO timestamps are recognized")
    parser.add_argument("--max-mib-per-file", type=int, default=256, help="Read at most this many MiB per log file (default: 256)")
    parser.add_argument("logs", nargs="+", help="Explicit log paths; .gz files are supported")
    args = parser.parse_args()
    if args.max_mib_per_file < 1:
        parser.error("--max-mib-per-file must be at least 1")
    try:
        after = parse_after(args.after) if args.after else None
    except (ValueError, OverflowError) as exc:
        parser.error(str(exc))

    byte_limit = args.max_mib_per_file * 1024 * 1024
    results = []
    had_error = False
    for raw_path in args.logs:
        path = Path(raw_path)
        counts = {name: 0 for name in PATTERNS}
        lines_scanned = 0
        bytes_scanned = 0
        unparsed_timestamps = 0
        oversized_lines_skipped = 0
        truncated = False
        error = None

        try:
            opener = gzip.open if path.name.endswith(".gz") else open
            with opener(path, "rb") as stream:
                while bytes_scanned < byte_limit:
                    line = stream.readline(min(MAX_LINE_BYTES + 1, byte_limit - bytes_scanned))
                    if not line:
                        break
                    bytes_scanned += len(line)
                    lines_scanned += 1
                    if bytes_scanned >= byte_limit and not line.endswith(b"\n"):
                        truncated = True
                        break
                    if len(line) > MAX_LINE_BYTES:
                        oversized_lines_skipped += 1
                        while not line.endswith(b"\n") and bytes_scanned < byte_limit:
                            line = stream.readline(min(64 * 1024, byte_limit - bytes_scanned))
                            if not line:
                                break
                            bytes_scanned += len(line)
                        if bytes_scanned >= byte_limit and (not line or not line.endswith(b"\n")):
                            truncated = True
                            break
                        if after is not None:
                            unparsed_timestamps += 1
                        continue
                    if after is not None:
                        timestamp = parse_timestamp(line)
                        if timestamp is None:
                            unparsed_timestamps += 1
                            continue
                        if timestamp < after:
                            continue
                    for name, pattern in PATTERNS.items():
                        if pattern.search(line):
                            counts[name] += 1
                if bytes_scanned >= byte_limit and not truncated and stream.read(1):
                    truncated = True
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            error = f"{type(exc).__name__}: {exc}"
            had_error = True

        results.append(
            {
                "path": str(path),
                "lines_scanned": lines_scanned,
                "bytes_scanned": bytes_scanned,
                "unparsed_timestamps_excluded": unparsed_timestamps,
                "oversized_lines_skipped": oversized_lines_skipped,
                "truncated_by_byte_limit": truncated,
                "counts": counts,
                "error": error,
            }
        )

    report = {
        "after_utc": after.isoformat() if after else None,
        "results": results,
        "interpretation": "These generic error counts are investigation leads, not exploit indicators or proof of compromise. Correlate with request logs, deployment history, and the current official advisory.",
        "privacy": "Matched log lines, request data, addresses, and credentials are not emitted.",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if had_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
