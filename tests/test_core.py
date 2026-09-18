import subprocess
from pathlib import Path

from reboot_safety_check.core import (
    DkmsEntry,
    collect_and_evaluate,
    evaluate,
    find_installed_kernels,
    get_enrolled_mok_count,
    get_running_kernel,
    headers_installed,
    module_signature_status,
    parse_dkms_status,
    run_dkms_status,
    secure_boot_enabled,
    _version_key,
)


def test_version_key_orders_numeric_parts_correctly():
    versions = ["6.8.0-51-generic", "6.13.1-arch1-1", "5.15.0-100-generic"]
    ordered = sorted(versions, key=_version_key)
    assert ordered == ["5.15.0-100-generic", "6.8.0-51-generic", "6.13.1-arch1-1"]


def test_find_installed_kernels_lists_directories(tmp_path):
    (tmp_path / "6.8.0-51-generic").mkdir()
    (tmp_path / "6.9.0-1-generic").mkdir()
    (tmp_path / "not_a_kernel.txt").write_text("x")
    result = find_installed_kernels(modules_root=tmp_path)
    assert result == ["6.8.0-51-generic", "6.9.0-1-generic"]


def test_find_installed_kernels_missing_root_returns_empty(tmp_path):
    assert find_installed_kernels(modules_root=tmp_path / "does_not_exist") == []


def test_get_running_kernel_parses_uname(monkeypatch):
    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="6.8.0-51-generic\n", stderr="")

    assert get_running_kernel(runner=fake_runner) == "6.8.0-51-generic"


def test_get_running_kernel_handles_failure():
    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="err")

    assert get_running_kernel(runner=fake_runner) is None


SAMPLE_DKMS_OUTPUT = """
nvidia/570.86.15, 6.8.0-51-generic, x86_64: installed
nvidia/570.86.15, 6.9.0-1-generic, x86_64: added
rtl8812au/5.13.6.r61.gad90dfb, 6.8.0-51-generic: installed
"""


def test_parse_dkms_status_extracts_all_fields():
    entries = parse_dkms_status(SAMPLE_DKMS_OUTPUT)
    assert len(entries) == 3
    assert entries[0] == DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "installed")
    assert entries[1].status == "added"
    assert entries[2].module == "rtl8812au"


def test_parse_dkms_status_ignores_blank_and_unmatched_lines():
    entries = parse_dkms_status("\n\nsome unrelated banner text\n")
    assert entries == []


def test_evaluate_flags_missing_build_for_new_kernel():
    dkms_entries = [DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "installed")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert report.has_warnings
    assert any("6.9.0-1-generic" in f.message for f in report.findings)


def test_evaluate_unknown_running_kernel_does_not_false_positive():
    # Regression test: when `uname -r` fails/is unavailable, running_kernel
    # is None. Previously `installed_kernels if k != running_kernel` treated
    # every installed kernel (including the one actually booted and
    # working fine) as "not yet booted", so a module that is merely
    # 'built' (not fully 'installed') for the CURRENTLY RUNNING kernel was
    # wrongly reported as a "fail" -- even though the system is booted and
    # working right now. The tool must not fabricate a failure finding
    # against a kernel it cannot even identify; it should say "unknown"
    # instead.
    dkms_entries = [DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "built")]
    report = evaluate(
        running_kernel=None,
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert not report.has_failures
    assert any(
        "could not determine the currently running kernel" in f.message.lower()
        and f.level == "warn"
        for f in report.findings
    )


def test_evaluate_ignores_older_already_booted_fallback_kernel():
    # Regression test: distros commonly keep 1-2 OLDER kernel packages
    # installed as a rollback fallback (apt/dnf retain-old-kernels
    # behavior) alongside the currently running (newest) kernel. Those
    # older kernels have, by definition, already booted successfully in
    # the past -- they are not "installed but not yet booted" in the
    # sense this tool's own README/docstring describe ("a kernel you've
    # just installed but haven't booted into yet"). Previously
    # `installed_kernels if k != running_kernel` treated *any* other
    # installed kernel -- older or newer -- as not-yet-booted, so a
    # stale/absent DKMS registration for an old fallback kernel produced
    # a false "fail"/"warn" finding against a kernel that isn't actually
    # at risk of the never-booted-broken-module failure mode.
    dkms_entries = [
        DkmsEntry("nvidia", "570.86.15", "6.9.0-1-generic", "installed"),
        DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "built"),
    ]
    report = evaluate(
        running_kernel="6.9.0-1-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert not report.has_failures
    assert not report.has_warnings
    assert not any("6.8.0-51-generic" in f.message for f in report.findings)


def test_evaluate_still_flags_missing_build_for_genuinely_newer_kernel():
    # Companion to the above: a NEWER installed-but-not-yet-booted kernel
    # must still be checked and flagged -- the fix must not suppress the
    # tool's actual purpose, only stop misapplying it to older kernels.
    dkms_entries = [
        DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "installed"),
        DkmsEntry("nvidia", "570.86.15", "6.9.0-1-generic", "built"),
    ]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert report.has_failures
    assert any("6.9.0-1-generic" in f.message and f.level == "fail" for f in report.findings)


def test_evaluate_flags_added_but_not_installed_as_failure():
    dkms_entries = [
        DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "installed"),
        DkmsEntry("nvidia", "570.86.15", "6.9.0-1-generic", "added"),
    ]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert report.has_failures
    assert any("added" in f.message and f.level == "fail" for f in report.findings)


def test_evaluate_flags_missing_headers():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.9.0-1-generic", "installed")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: False,
        secure_boot_checker=lambda: False,
    )
    assert report.has_failures
    assert any("headers" in f.message for f in report.findings)


def test_evaluate_clean_system_has_no_warnings_or_failures():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert not report.has_failures
    assert not report.has_warnings
    assert any("all registered" in f.message.lower() for f in report.findings)


def test_evaluate_no_dkms_modules_is_informational_only():
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=[],
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert not report.has_failures
    assert not report.has_warnings
    assert any("no dkms modules" in f.message.lower() for f in report.findings)


def test_evaluate_secure_boot_adds_info_finding_when_modules_present():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: True,
        mok_count_checker=lambda: None,
        module_signature_checker=lambda module, kernel: None,
    )
    assert any("secure boot" in f.message.lower() for f in report.findings)


def test_evaluate_secure_boot_no_enrolled_mok_is_failure():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: True,
        mok_count_checker=lambda: 0,
        module_signature_checker=lambda module, kernel: None,
    )
    assert report.has_failures
    assert any("no enrolled" in f.message.lower() for f in report.findings)


def test_evaluate_secure_boot_unsigned_module_for_new_kernel_is_failure():
    dkms_entries = [
        DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed"),
        DkmsEntry("nvidia", "1.0", "6.9.0-1-generic", "installed"),
    ]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: True,
        mok_count_checker=lambda: 1,
        module_signature_checker=lambda module, kernel: kernel != "6.9.0-1-generic",
    )
    assert report.has_failures
    assert any(
        "no signature" in f.message.lower() and "6.9.0-1-generic" in f.message
        for f in report.findings
    )


def test_evaluate_secure_boot_signed_module_with_enrolled_mok_is_clean():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed")]
    report = evaluate(
        running_kernel="",  # nothing is "not yet booted" so no signature checks run
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: True,
        mok_count_checker=lambda: 1,
        module_signature_checker=lambda module, kernel: True,
    )
    assert not report.has_failures


def test_get_enrolled_mok_count_parses_key_headers(monkeypatch):
    from reboot_safety_check.core import get_enrolled_mok_count
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")
    sample = "[key 1]\nSHA1 Fingerprint: aa:bb\n\tSubject: CN=Test\n[key 2]\nSHA1 Fingerprint: cc:dd\n"

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=sample, stderr="")

    assert get_enrolled_mok_count(runner=fake_runner) == 2


def test_get_enrolled_mok_count_zero_when_nothing_enrolled(monkeypatch):
    from reboot_safety_check.core import get_enrolled_mok_count
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="No MOK certificates are enrolled\n", stderr="")

    assert get_enrolled_mok_count(runner=fake_runner) == 0


def test_get_enrolled_mok_count_none_on_failure(monkeypatch):
    from reboot_safety_check.core import get_enrolled_mok_count
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="err")

    assert get_enrolled_mok_count(runner=fake_runner) is None


def test_module_signature_status_true_when_signer_present(monkeypatch):
    from reboot_safety_check.core import module_signature_status
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/modinfo")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout="filename: nvidia.ko\nsigner: Test MOK\nsig_key: 01:02\n", stderr=""
        )

    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=fake_runner) is True


def test_module_signature_status_false_when_no_signer(monkeypatch):
    from reboot_safety_check.core import module_signature_status
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/modinfo")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="filename: nvidia.ko\nlicense: GPL\n", stderr="")

    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=fake_runner) is False


def test_module_signature_status_none_on_failure(monkeypatch):
    from reboot_safety_check.core import module_signature_status
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/modinfo")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")

    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=fake_runner) is None


def test_get_enrolled_mok_count_none_when_mokutil_missing(monkeypatch):
    from reboot_safety_check.core import get_enrolled_mok_count
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: None)
    assert get_enrolled_mok_count(runner=lambda *a, **k: None) is None


def test_module_signature_status_none_when_modinfo_missing(monkeypatch):
    from reboot_safety_check.core import module_signature_status
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: None)
    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=lambda *a, **k: None) is None


# --- run_dkms_status ---------------------------------------------------


def test_run_dkms_status_none_when_dkms_missing(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: None)
    assert run_dkms_status(runner=lambda *a, **k: None) is None


def test_run_dkms_status_returns_stdout(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/dkms")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=SAMPLE_DKMS_OUTPUT, stderr="")

    assert run_dkms_status(runner=fake_runner) == SAMPLE_DKMS_OUTPUT


def test_run_dkms_status_none_on_oserror(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/dkms")

    def raising_runner(cmd, **kwargs):
        raise OSError("dkms vanished")

    assert run_dkms_status(runner=raising_runner) is None


# --- get_running_kernel ---------------------------------------------------


def test_get_running_kernel_none_on_oserror():
    def raising_runner(cmd, **kwargs):
        raise OSError("uname missing")

    assert get_running_kernel(runner=raising_runner) is None


# --- headers_installed ---------------------------------------------------


def test_headers_installed_dpkg_true(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="install ok installed", stderr="")

    assert headers_installed("6.8.0-51-generic", runner=fake_runner) is True


def test_headers_installed_dpkg_false_on_nonzero(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")

    assert headers_installed("6.8.0-51-generic", runner=fake_runner) is False


def test_headers_installed_dpkg_false_on_removed_config_files_state(monkeypatch):
    """dpkg-query -W exits 0 even for a package it still knows about but
    that isn't actually installed (e.g. removed with config kept). This
    must report False (a real "headers missing" finding), not fall through
    to None ("unknown, no finding") and silently hide the problem."""
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="deinstall ok config-files", stderr="")

    assert headers_installed("6.8.0-51-generic", runner=fake_runner) is False


def test_headers_installed_dpkg_oserror_returns_none(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/dpkg-query" if name == "dpkg-query" else None)

    def raising_runner(cmd, **kwargs):
        raise OSError("dpkg-query missing")

    assert headers_installed("6.8.0-51-generic", runner=raising_runner) is None


def test_headers_installed_rpm_true(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/rpm" if name == "rpm" else None)

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="kernel-devel-6.8.0-51-generic", stderr="")

    assert headers_installed("6.8.0-51-generic", runner=fake_runner) is True


def test_headers_installed_rpm_false_on_nonzero(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/rpm" if name == "rpm" else None)

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="not found")

    assert headers_installed("6.8.0-51-generic", runner=fake_runner) is False


def test_headers_installed_rpm_oserror_returns_none(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/rpm" if name == "rpm" else None)

    def raising_runner(cmd, **kwargs):
        raise OSError("rpm missing")

    assert headers_installed("6.8.0-51-generic", runner=raising_runner) is None


def test_headers_installed_none_when_neither_dpkg_nor_rpm(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: None)
    assert headers_installed("6.8.0-51-generic", runner=lambda *a, **k: None) is None


# --- secure_boot_enabled ---------------------------------------------------


def test_secure_boot_enabled_none_when_mokutil_missing(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: None)
    assert secure_boot_enabled(runner=lambda *a, **k: None) is None


def test_secure_boot_enabled_true(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="SecureBoot enabled\n", stderr="")

    assert secure_boot_enabled(runner=fake_runner) is True


def test_secure_boot_enabled_false(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="SecureBoot disabled\n", stderr="")

    assert secure_boot_enabled(runner=fake_runner) is False


def test_secure_boot_enabled_none_on_nonzero_returncode(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="err")

    assert secure_boot_enabled(runner=fake_runner) is None


def test_secure_boot_enabled_none_when_state_undeterminable(monkeypatch):
    """mokutil --sb-state exits 0 even when it prints "Cannot determine
    secure boot state." (e.g. non-UEFI host, unreadable EFI vars). That
    must report None (unknown), never a false "disabled"."""
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def fake_runner(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Cannot determine secure boot state.\n", stderr=""
        )

    assert secure_boot_enabled(runner=fake_runner) is None


def test_secure_boot_enabled_none_on_oserror(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def raising_runner(cmd, **kwargs):
        raise OSError("mokutil vanished")

    assert secure_boot_enabled(runner=raising_runner) is None


def test_get_enrolled_mok_count_none_on_oserror(monkeypatch):
    """Regression test: get_enrolled_mok_count's own try/except around
    `mokutil --list-enrolled` was exercised only via a returncode!=0
    fake runner (test_get_enrolled_mok_count_none_on_failure), never via
    the runner itself raising OSError/SubprocessError -- the actual
    exception branch at core.py's `except (OSError, subprocess.SubprocessError)`
    for this function had zero coverage before this test."""
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def raising_runner(cmd, **kwargs):
        raise OSError("mokutil vanished")

    assert get_enrolled_mok_count(runner=raising_runner) is None


def test_get_enrolled_mok_count_none_on_timeout(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/bin/mokutil")

    def raising_runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 10)

    assert get_enrolled_mok_count(runner=raising_runner) is None


def test_module_signature_status_none_on_oserror(monkeypatch):
    """Regression test: module_signature_status's try/except around
    `modinfo -k KERNEL MODULE` was exercised only via a nonzero
    returncode fake runner (test_module_signature_status_none_on_failure),
    never via the runner itself raising OSError/SubprocessError -- the
    actual exception branch had zero coverage before this test."""
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/modinfo")

    def raising_runner(cmd, **kwargs):
        raise OSError("modinfo vanished")

    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=raising_runner) is None


def test_module_signature_status_none_on_timeout(monkeypatch):
    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(core_mod.shutil, "which", lambda name: "/usr/sbin/modinfo")

    def raising_runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 10)

    assert module_signature_status("nvidia", "6.9.0-1-generic", runner=raising_runner) is None


def test_evaluate_broken_dkms_module_is_failure():
    # Regression test: dkms(8) documents "broken" as a genuine, well-defined
    # status (source directory or 'source' symlink missing; dkms refuses to
    # build/install until manually re-added) -- a real failure, not merely an
    # "unexpected" string. Before this fix, "broken" fell into the same
    # generic warn-level "unexpected status" bucket as a truly unrecognized
    # value, understating its severity (a module dkms cannot rebuild at all
    # is strictly worse than one that is merely 'added'/'built').
    dkms_entries = [
        DkmsEntry("nvidia", "570.86.15", "6.8.0-51-generic", "installed"),
        DkmsEntry("nvidia", "570.86.15", "6.9.0-1-generic", "broken"),
    ]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert report.has_failures
    assert any(
        "broken" in f.message.lower() and f.level == "fail" and "6.9.0-1-generic" in f.message
        for f in report.findings
    )


def test_evaluate_installed_with_diff_warning_is_flagged_specifically():
    # Regression test: real-world `dkms status` output (see e.g. askubuntu
    # 1246534, common on Ubuntu NVIDIA-driver systems) can report a module
    # as "installed" while ALSO appending "(WARNING! Diff between built and
    # installed module!)" -- meaning the .ko actually present under
    # /lib/modules/<kernel> no longer matches what dkms itself built and
    # verified (commonly because a package manager reinstalled/overwrote it
    # afterward). Before this fix, this real status string did not match the
    # exact "installed" in DKMS_GOOD_STATUSES, so it fell through to the
    # generic, vague "unexpected status" warning -- never explaining the
    # actual risk (module that loads after reboot may not be the verified
    # one) or the fix (`dkms install --force`).
    dkms_entries = [
        DkmsEntry(
            "nvidia",
            "570.86.15",
            "6.9.0-1-generic",
            "installed (WARNING! Diff between built and installed module!)",
        ),
    ]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert not report.has_failures
    assert report.has_warnings
    assert any(
        "diff between the built and installed module" in f.message.lower()
        and "--force" in f.message
        and f.level == "warn"
        for f in report.findings
    )
    assert not any("unexpected status" in f.message.lower() for f in report.findings)


# --- evaluate: unexpected DKMS status branch ------------------------------


def test_evaluate_unexpected_dkms_status_is_warning():
    dkms_entries = [DkmsEntry("nvidia", "1.0", "6.9.0-1-generic", "weird-status")]
    report = evaluate(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic", "6.9.0-1-generic"],
        dkms_entries=dkms_entries,
        headers_checker=lambda k: True,
        secure_boot_checker=lambda: False,
    )
    assert report.has_warnings
    assert any(
        "unexpected status" in f.message.lower() and f.level == "warn" for f in report.findings
    )


# --- collect_and_evaluate: real end-to-end wiring -------------------------


def test_collect_and_evaluate_wires_all_checks_together(tmp_path, monkeypatch):
    (tmp_path / "6.8.0-51-generic").mkdir()
    (tmp_path / "6.9.0-1-generic").mkdir()

    def fake_runner(cmd, **kwargs):
        exe = cmd[0]
        if exe.endswith("uname"):
            return subprocess.CompletedProcess(cmd, 0, stdout="6.8.0-51-generic\n", stderr="")
        if exe.endswith("dkms"):
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout="nvidia/1.0, 6.8.0-51-generic, x86_64: installed\n",
                stderr="",
            )
        if exe.endswith("mokutil") and cmd[1:] == ["--sb-state"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="SecureBoot disabled\n", stderr="")
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    import reboot_safety_check.core as core_mod

    monkeypatch.setattr(
        core_mod.shutil,
        "which",
        lambda name: f"/usr/bin/{name}" if name in ("dkms", "mokutil") else None,
    )
    monkeypatch.setattr(core_mod, "subprocess", subprocess)

    report = collect_and_evaluate(modules_root=tmp_path, runner=fake_runner)

    assert report.running_kernel == "6.8.0-51-generic"
    assert report.installed_kernels == ["6.8.0-51-generic", "6.9.0-1-generic"]
    # 6.9.0-1-generic has no DKMS build registered at all -> warning finding.
    assert any("6.9.0-1-generic" in f.message for f in report.findings)
