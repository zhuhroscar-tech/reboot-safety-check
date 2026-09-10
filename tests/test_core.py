import subprocess
from pathlib import Path

from reboot_safety_check.core import (
    DkmsEntry,
    evaluate,
    find_installed_kernels,
    get_running_kernel,
    parse_dkms_status,
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
