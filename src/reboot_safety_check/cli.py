"""reboot-safety-check CLI."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__
from .core import collect_and_evaluate


LEVEL_ICON = {"fail": "FAIL", "warn": "WARN", "info": "info"}


def _print_human(report) -> None:
    print(f"Running kernel:    {report.running_kernel or 'unknown'}")
    print(f"Installed kernels: {', '.join(report.installed_kernels) or 'none found'}")
    print(f"DKMS modules seen: {', '.join(sorted({e.module for e in report.dkms_entries})) or 'none'}")
    print()
    for f in report.findings:
        print(f"[{LEVEL_ICON.get(f.level, f.level.upper())}] {f.message}")
    print()
    if report.has_failures:
        print("Result: NOT SAFE to reboot yet -- see FAIL lines above.")
    elif report.has_warnings:
        print("Result: probably fine, but review the WARN lines above before rebooting.")
    else:
        print("Result: looks safe to reboot.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reboot-safety-check",
        description=(
            "Warn about DKMS kernel-module problems (missing build, missing headers, "
            "Secure Boot signing risk) for any installed-but-not-yet-booted kernel, "
            "before you reboot into it. Read-only: never modifies anything."
        ),
    )
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = collect_and_evaluate()

    if args.json:
        out = {
            "running_kernel": report.running_kernel,
            "installed_kernels": report.installed_kernels,
            "dkms_entries": [asdict(e) for e in report.dkms_entries],
            "findings": [asdict(f) for f in report.findings],
            "has_failures": report.has_failures,
            "has_warnings": report.has_warnings,
        }
        print(json.dumps(out, indent=2))
    else:
        _print_human(report)

    if report.has_failures:
        return 2
    if report.has_warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
