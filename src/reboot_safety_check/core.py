"""Core checks for reboot-safety-check.

The problem this solves: on Linux distros using DKMS (out-of-tree kernel
modules — proprietary NVIDIA/AMD GPU drivers, Wi-Fi drivers like
rtl8812au/rtl8852au, VirtualBox host modules, ZFS, ...), installing a new
kernel package does *not* guarantee the DKMS module was successfully rebuilt
for it. If the build silently fails (missing kernel headers, a compiler
incompatibility, a kernel API change the module hasn't caught up with yet),
the system boots into the new kernel with the module simply absent — no GPU
driver, no Wi-Fi, no VirtualBox — and the user only discovers this *after*
rebooting, per the extensive Arch/Ubuntu/Fedora forum and bug-tracker history
of this exact failure mode.

This tool is a read-only pre-reboot sanity check: it inspects the currently
*installed* kernels, cross-references `dkms status` for each registered DKMS
module, and reports which combinations are missing a successfully built
module for a newer, not-yet-booted kernel — so the user can fix it (rebuild,
install headers, pin the kernel) *before* rebooting into a broken system.

It never modifies anything: no `dkms install`, no `apt`/`dnf`/`pacman`
invocation, no `reboot`. Read-only inspection only.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# --- kernel version comparison -------------------------------------------

_VERSION_SPLIT_RE = re.compile(r"[.\-+]")


def _version_key(version: str):
    """Best-effort sortable key for kernel version strings like
    '6.8.0-51-generic' or '6.13.1-arch1-1', so we can find the 'newest'
    installed kernel without needing `sort -V` semantics baked in twice."""
    parts = _VERSION_SPLIT_RE.split(version)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return key


# --- installed kernels ------------------------------------------------------


def find_installed_kernels(modules_root: Path = Path("/lib/modules")) -> list:
    """List kernel versions that have a modules directory installed.

    This intentionally does not require `uname -r` to be one of them --
    the whole point is to also catch kernels that were *just* installed
    but not yet booted into.
    """
    if not modules_root.is_dir():
        return []
    versions = [p.name for p in modules_root.iterdir() if p.is_dir()]
    return sorted(versions, key=_version_key)


def get_running_kernel(runner=subprocess.run) -> Optional[str]:
    try:
        proc = runner(["uname", "-r"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


# --- dkms status parsing -----------------------------------------------------

# Typical dkms status line (older/newer dkms versions vary slightly, but all
# of these forms include module/version, kernel, arch, and a status word):
#   nvidia/570.86.15, 6.8.0-51-generic, x86_64: installed
#   rtl8812au/5.13.6.r61.gad90dfb, 6.13.1-arch1-1: added
_DKMS_LINE_RE = re.compile(
    r"^(?P<module>[^/,]+)/(?P<mod_version>[^,]+),\s*"
    r"(?P<kernel>[^,]+?)(?:,\s*(?P<arch>\S+))?\s*:\s*(?P<status>.+)$"
)


@dataclass
class DkmsEntry:
    module: str
    mod_version: str
    kernel: str
    status: str


def parse_dkms_status(output: str) -> list:
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _DKMS_LINE_RE.match(line)
        if not m:
            continue
        entries.append(
            DkmsEntry(
                module=m.group("module"),
                mod_version=m.group("mod_version"),
                kernel=m.group("kernel").strip(),
                status=m.group("status").strip(),
            )
        )
    return entries


def run_dkms_status(runner=subprocess.run) -> Optional[str]:
    dkms_bin = shutil.which("dkms")
    if not dkms_bin:
        return None
    try:
        proc = runner([dkms_bin, "status"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout or ""


# --- headers presence ---------------------------------------------------


def headers_installed(kernel_version: str, runner=subprocess.run) -> Optional[bool]:
    """Best-effort check for kernel headers matching kernel_version.

    Returns True/False when determinable, None when we couldn't tell on
    this distro (no dpkg/rpm, or the path convention is unrecognized) --
    callers should treat None as 'unknown, not a finding'.
    """
    # Debian/Ubuntu
    if shutil.which("dpkg-query"):
        try:
            proc = runner(
                ["dpkg-query", "-W", "-f=${Status}", f"linux-headers-{kernel_version}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode == 0 and "install ok installed" in proc.stdout:
            return True
        if proc.returncode != 0:
            return False
    # Fedora/RHEL
    if shutil.which("rpm"):
        try:
            proc = runner(
                ["rpm", "-q", f"kernel-devel-{kernel_version}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.returncode == 0
    return None


# --- secure boot ----------------------------------------------------------


def secure_boot_enabled(runner=subprocess.run) -> Optional[bool]:
    mokutil = shutil.which("mokutil")
    if not mokutil:
        return None
    try:
        proc = runner([mokutil, "--sb-state"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return "secureboot enabled" in proc.stdout.lower()


def get_enrolled_mok_count(runner=subprocess.run) -> Optional[int]:
    """Count how many MOK (Machine Owner Key) certificates are enrolled.

    Returns 0 if Secure Boot tooling is present but nothing is enrolled
    (the "built the module, forgot to enroll a key" failure mode), a
    positive int if keys are enrolled, or None if we couldn't determine
    this (no mokutil, or the command failed for another reason).
    """
    mokutil = shutil.which("mokutil")
    if not mokutil:
        return None
    try:
        proc = runner([mokutil, "--list-enrolled"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    # Each enrolled certificate block starts with a header line like "[key 1]".
    count = len(re.findall(r"^\[key\s+\d+\]", proc.stdout, re.MULTILINE))
    if count == 0 and "sbat" not in proc.stdout.lower() and proc.stdout.strip():
        # Some mokutil versions print a plain human sentence instead of
        # bracketed headers when nothing is enrolled -- treat any non-empty,
        # non-error output without a recognized enrolled-key header as zero.
        return 0
    return count


def module_signature_status(module: str, kernel: str, runner=subprocess.run) -> Optional[bool]:
    """Best-effort check of whether `module` is cryptographically signed
    for `kernel`, via `modinfo -k KERNEL MODULE`.

    Returns True if a signer/signature field is present, False if modinfo
    ran successfully but found no such field (module is unsigned), or
    None if this couldn't be determined (missing modinfo, module not
    found for that kernel, etc.) -- callers should treat None as
    'unknown, not a finding', consistent with the rest of this module.
    """
    modinfo = shutil.which("modinfo")
    if not modinfo:
        return None
    try:
        proc = runner(
            [modinfo, "-k", kernel, module], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    out = proc.stdout.lower()
    return "signer:" in out or "sig_id:" in out


# --- putting it together --------------------------------------------------


@dataclass
class Finding:
    level: str  # "fail" | "warn" | "info"
    message: str


@dataclass
class Report:
    running_kernel: Optional[str]
    installed_kernels: list
    dkms_entries: list
    findings: list = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        return any(f.level == "fail" for f in self.findings)

    @property
    def has_warnings(self) -> bool:
        return any(f.level == "warn" for f in self.findings)


DKMS_GOOD_STATUSES = {"installed"}
DKMS_BAD_STATUSES = {"added", "built"}  # registered/compiled but not installed for that kernel


def evaluate(
    running_kernel: Optional[str],
    installed_kernels: list,
    dkms_entries: list,
    headers_checker=headers_installed,
    secure_boot_checker=secure_boot_enabled,
    mok_count_checker=get_enrolled_mok_count,
    module_signature_checker=module_signature_status,
) -> Report:
    findings: list = []

    modules = sorted({e.module for e in dkms_entries})

    not_yet_booted = [k for k in installed_kernels if k != running_kernel]

    for kernel in not_yet_booted:
        for module in modules:
            matches = [e for e in dkms_entries if e.module == module and e.kernel == kernel]
            if not matches:
                findings.append(
                    Finding(
                        "warn",
                        f"DKMS module '{module}' has no build registered for installed-but-"
                        f"not-yet-booted kernel {kernel}. If you reboot into this kernel, "
                        f"'{module}' may be missing.",
                    )
                )
                continue
            for m in matches:
                if m.status.lower() in DKMS_GOOD_STATUSES:
                    continue
                if m.status.lower() in DKMS_BAD_STATUSES:
                    findings.append(
                        Finding(
                            "fail",
                            f"DKMS module '{module}' for kernel {kernel} is only "
                            f"'{m.status}', not fully installed. This module likely "
                            f"will not load after rebooting into {kernel}.",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            "warn",
                            f"DKMS module '{module}' for kernel {kernel} has unexpected "
                            f"status '{m.status}'.",
                        )
                    )

        headers_ok = headers_checker(kernel)
        if headers_ok is False and modules:
            findings.append(
                Finding(
                    "fail",
                    f"Kernel headers for {kernel} are not installed. Any DKMS module "
                    f"will fail to (re)build against this kernel until headers are added.",
                )
            )

    sb = secure_boot_checker()
    if sb is True and modules:
        mok_count = mok_count_checker()
        if mok_count == 0:
            findings.append(
                Finding(
                    "fail",
                    "Secure Boot is enabled, you have DKMS modules registered, but "
                    "`mokutil --list-enrolled` reports NO enrolled Machine Owner Keys. "
                    "A DKMS build can succeed and still be refused at load time with "
                    "no enrolled key to trust it -- run `mokutil --import <your.der>` "
                    "and complete enrollment at the blue MokManager screen on next boot.",
                )
            )
        else:
            # Enrolled keys exist (or we couldn't count them) -- fall through to
            # a signature spot-check per not-yet-booted kernel/module pair so we
            # catch the "signed with a key that isn't the enrolled one" case too.
            for kernel in not_yet_booted:
                for module in modules:
                    signed = module_signature_checker(module, kernel)
                    if signed is False:
                        findings.append(
                            Finding(
                                "fail",
                                f"Secure Boot is enabled but DKMS module '{module}' for "
                                f"kernel {kernel} has no signature (`modinfo` shows no "
                                f"signer). It will be refused at load time after "
                                f"rebooting into {kernel} unless it gets (re)signed.",
                            )
                        )
            if mok_count is None:
                findings.append(
                    Finding(
                        "info",
                        "Secure Boot is enabled and you have DKMS modules registered. "
                        "Unsigned/unenrolled modules will be silently refused at load "
                        "time even if the build succeeds -- verify your MOK is "
                        "enrolled (`mokutil --list-enrolled`) if a module unexpectedly "
                        "fails to load.",
                    )
                )

    if not modules:
        findings.append(Finding("info", "No DKMS modules registered on this system."))
    elif not findings:
        findings.append(
            Finding("info", "All registered DKMS modules look installed for every installed kernel.")
        )

    return Report(
        running_kernel=running_kernel,
        installed_kernels=installed_kernels,
        dkms_entries=dkms_entries,
        findings=findings,
    )


def collect_and_evaluate(
    modules_root: Path = Path("/lib/modules"),
    runner=subprocess.run,
) -> Report:
    running_kernel = get_running_kernel(runner=runner)
    installed_kernels = find_installed_kernels(modules_root=modules_root)
    dkms_output = run_dkms_status(runner=runner)
    dkms_entries = parse_dkms_status(dkms_output) if dkms_output is not None else []

    def _headers(kernel_version):
        return headers_installed(kernel_version, runner=runner)

    def _secure_boot():
        return secure_boot_enabled(runner=runner)

    def _mok_count():
        return get_enrolled_mok_count(runner=runner)

    def _module_signature(module, kernel):
        return module_signature_status(module, kernel, runner=runner)

    return evaluate(
        running_kernel,
        installed_kernels,
        dkms_entries,
        headers_checker=_headers,
        secure_boot_checker=_secure_boot,
        mok_count_checker=_mok_count,
        module_signature_checker=_module_signature,
    )
