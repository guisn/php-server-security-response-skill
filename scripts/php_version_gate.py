#!/usr/bin/env python3
"""Compare an observed PHP version with the PHP project's upstream fix floor."""

from __future__ import annotations

import argparse
import json
import re
import sys


FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
CVE_IDS = ["CVE-2026-109618", "CVE-2026-109619"]


def version_text(parts: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in parts)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Preliminary check against PHP upstream fixes for CVE-2026-109618/109619."
    )
    parser.add_argument("version", help="One observed runtime version or its `php -v` output, for example 'PHP 8.3.35'")
    args = parser.parse_args()

    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", args.version)
    if not match:
        print("Could not parse a PHP x.y.z version from the input.", file=sys.stderr)
        return 2

    observed = tuple(int(part) for part in match.groups())
    branch = observed[:2]
    floor = FIXED.get(branch)
    suffix = args.version[match.end() : match.end() + 32]
    prerelease = re.match(r"(?:[-+.]?)(?:dev|alpha|beta|rc|snapshot)\d*\b", suffix, re.IGNORECASE)
    if prerelease and floor is not None:
        result = "pre_release_requires_manual_verification"
        floor_text = version_text(floor)
        notes = [
            "The version string contains a development or release-candidate marker; do not treat its numeric portion as a stable patched release.",
            "Verify the exact build and vendor advisory before assigning a final status.",
        ]
    elif floor is None:
        result = "vendor_or_source_patch_confirmation_required"
        floor_text = None
        notes = [
            "No upstream fixed-version floor is recorded here for this branch.",
            "PHP 8.1 and older require explicit vendor/backport evidence or a migration plan.",
            "Do not infer vulnerable or fixed status from the version string alone.",
        ]
    elif observed < floor:
        result = "below_upstream_fixed_version"
        floor_text = version_text(floor)
        notes = [
            "The version is below the PHP project's fixed release for this branch.",
            "A distribution or LTS vendor may have backported the fix; verify package provenance and advisory evidence before concluding.",
        ]
    else:
        result = "at_or_above_upstream_fixed_version"
        floor_text = version_text(floor)
        notes = [
            "The version string meets the PHP project's fixed release floor for this branch.",
            "Confirm that this is the runtime serving web requests and that workers, cron jobs, and replicas are covered.",
        ]

    report = {
        "cves": CVE_IDS,
        "observed_version": version_text(observed),
        "branch": f"{branch[0]}.{branch[1]}",
        "upstream_fixed_floor": floor_text,
        "preliminary_result": result,
        "notes": notes,
        "limitations": [
            "This is a version-string comparison, not a vulnerability scan or proof of compromise.",
            "Vendor backports, custom builds, and differences between CLI and web runtimes require separate verification.",
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
