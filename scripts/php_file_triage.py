#!/usr/bin/env python3
"""List metadata and hashes of recently modified files under explicit roots."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import stat


CODE_SUFFIXES = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8",
    ".phtml", ".phar", ".inc", ".user.ini", ".htaccess",
}


def parse_timestamp(value: str) -> dt.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--since must include a timezone, such as 2026-10-21T14:00:00Z")
    return parsed.astimezone(dt.timezone.utc)


def hash_file(path: str, expected: os.stat_result, max_bytes: int) -> tuple[str | None, str, int]:
    if not hasattr(os, "O_NOFOLLOW"):
        return None, "platform_no_nofollow_support", 0
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return None, "not_regular_file", 0
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            return None, "file_changed_before_hash", 0
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
            expected.st_size,
            expected.st_mtime_ns,
            expected.st_ctime_ns,
        ):
            return None, "file_changed_before_hash", 0
        if opened.st_size > max_bytes:
            return None, "file_exceeds_hash_read_budget", 0

        digest = hashlib.sha256()
        bytes_read = 0
        with os.fdopen(fd, "rb", closefd=False) as stream:
            while bytes_read < max_bytes:
                chunk = stream.read(min(1024 * 1024, max_bytes - bytes_read))
                if not chunk:
                    break
                bytes_read += len(chunk)
                digest.update(chunk)

        finished = os.fstat(fd)
        if (finished.st_size, finished.st_mtime_ns, finished.st_ctime_ns) != (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            return None, "file_changed_during_hash", bytes_read
        return digest.hexdigest(), "sha256", bytes_read
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only triage of recently modified files; prints metadata and hashes, never file contents."
    )
    parser.add_argument("--root", action="append", required=True, help="Directory to scan; repeat for each scoped application path")
    parser.add_argument("--since", required=True, help="Timezone-aware ISO-8601 timestamp, e.g. 2026-10-21T14:00:00Z")
    parser.add_argument("--max-depth", type=int, default=12, help="Maximum directory depth below each root (default: 12)")
    parser.add_argument("--max-files-scanned", type=int, default=50000, help="Stop after this many files (default: 50000)")
    parser.add_argument("--max-directories-scanned", type=int, default=10000, help="Stop after this many directories, including roots (default: 10000)")
    parser.add_argument("--max-findings", type=int, default=2000, help="Stop after this many recent files (default: 2000)")
    parser.add_argument("--max-hash-mib", type=int, default=64, help="Hash files up to this size; larger files are listed without a hash (default: 64 MiB)")
    parser.add_argument("--max-total-hash-mib", type=int, default=512, help="Maximum total file content hashed (default: 512 MiB)")
    args = parser.parse_args()

    try:
        since = parse_timestamp(args.since)
    except (ValueError, OverflowError) as exc:
        parser.error(str(exc))
    if (
        args.max_depth < 0
        or args.max_files_scanned < 1
        or args.max_directories_scanned < 1
        or args.max_findings < 1
        or args.max_hash_mib < 0
        or args.max_total_hash_mib < 0
    ):
        parser.error("limits must be non-negative, and scan/findings limits must be at least 1")

    roots: list[str] = []
    for raw_root in args.root:
        if os.path.islink(raw_root):
            parser.error(f"root must not be a symbolic link: {raw_root}")
        if not os.path.isdir(raw_root):
            parser.error(f"root is not a directory: {raw_root}")
        roots.append(os.path.abspath(raw_root))
    if len(roots) > args.max_directories_scanned:
        parser.error("number of roots exceeds --max-directories-scanned")

    files_scanned = 0
    directories_scanned = 0
    directories_enqueued = len(roots)
    findings = 0
    bytes_hashed = 0
    unreadable_directories = 0
    unreadable_files = 0
    symlinks_skipped = 0
    depth_pruned_directories = 0
    truncated = False
    since_epoch = since.timestamp()
    max_hash_bytes = args.max_hash_mib * 1024 * 1024

    for root in roots:
        stack: list[tuple[str, int]] = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            directories_scanned += 1
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                symlinks_skipped += 1
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if depth < args.max_depth:
                                    if directories_enqueued >= args.max_directories_scanned:
                                        truncated = True
                                        break
                                    directories_enqueued += 1
                                    stack.append((entry.path, depth + 1))
                                else:
                                    depth_pruned_directories += 1
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue

                            files_scanned += 1
                            if files_scanned > args.max_files_scanned:
                                truncated = True
                                break
                            info = entry.stat(follow_symlinks=False)
                            if info.st_mtime < since_epoch:
                                continue

                            findings += 1
                            if findings > args.max_findings:
                                truncated = True
                                findings -= 1
                                break

                            remaining_hash_bytes = max(
                                0, args.max_total_hash_mib * 1024 * 1024 - bytes_hashed
                            )
                            per_file_budget = min(max_hash_bytes, remaining_hash_bytes)
                            if per_file_budget == 0 and info.st_size > 0:
                                status = (
                                    "total_hash_budget_exhausted"
                                    if remaining_hash_bytes == 0
                                    else "per_file_hash_limit_is_zero"
                                )
                                digest, hash_status, bytes_read = None, status, 0
                            else:
                                try:
                                    digest, hash_status, bytes_read = hash_file(
                                        entry.path, info, per_file_budget
                                    )
                                except OSError:
                                    digest, hash_status, bytes_read = None, "unreadable_or_changed", 0
                                    unreadable_files += 1
                            bytes_hashed += bytes_read

                            record = {
                                "type": "finding",
                                "path": entry.path,
                                "mtime_utc": dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(),
                                "size_bytes": info.st_size,
                                "mode_octal": oct(stat.S_IMODE(info.st_mode)),
                                "uid": info.st_uid,
                                "gid": info.st_gid,
                                "code_candidate_by_extension": (
                                    entry.name.lower() in {".htaccess", ".user.ini"}
                                    or os.path.splitext(entry.name)[1].lower() in CODE_SUFFIXES
                                ),
                                "sha256": digest,
                                "hash_status": hash_status,
                            }
                            print(json.dumps(record, ensure_ascii=False))
                        except OSError:
                            unreadable_files += 1
            except OSError:
                unreadable_directories += 1

            if truncated:
                break
        if truncated:
            break

    summary = {
        "type": "summary",
        "roots": roots,
        "since_utc": since.isoformat(),
        "files_scanned": min(files_scanned, args.max_files_scanned),
        "directories_scanned": directories_scanned,
        "recent_files_emitted": findings,
        "bytes_hashed": bytes_hashed,
        "unreadable_directories": unreadable_directories,
        "unreadable_files": unreadable_files,
        "symlinks_skipped": symlinks_skipped,
        "depth_pruned_directories": depth_pruned_directories,
        "truncated_by_limit": truncated,
        "limits": {
            "max_depth": args.max_depth,
            "max_files_scanned": args.max_files_scanned,
            "max_directories_scanned": args.max_directories_scanned,
            "max_findings": args.max_findings,
            "max_hash_mib_per_file": args.max_hash_mib,
            "max_total_hash_mib": args.max_total_hash_mib,
        },
        "interpretation": "Recent modification is a triage lead, not proof of malicious activity; compare with deployment records and a trusted baseline.",
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
