"""reboot-safety-check CLI."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__
from .core import collect_and_evaluate
from .style import resolve_style, status_headline


def _finding_line(style, finding) -> str:
    return status_headline(style, finding.level, finding.message)


def _print_human(report, style) -> None:
    print(f"Running kernel:    {style.bold(report.running_kernel or 'unknown')}")
    print(f"Installed kernels: {', '.join(report.installed_kernels) or style.dim('none found')}")
    seen_modules = ', '.join(sorted({e.module for e in report.dkms_entries})) or style.dim('none')
    print(f"DKMS modules seen: {seen_modules}")
    print()
    for f in report.findings:
        print(_finding_line(style, f))
    print()
    if report.has_failures:
        print(status_headline(style, "fail", "NOT SAFE to reboot yet -- see the findings above."))
    elif report.has_warnings:
        print(status_headline(style, "warn", "Probably fine -- review the warnings above before rebooting."))
    else:
        print(status_headline(style, "ok", "Looks safe to reboot."))


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
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
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
        style = resolve_style(no_color_flag=args.no_color)
        _print_human(report, style)

    if report.has_failures:
        return 2
    if report.has_warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
