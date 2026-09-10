import json

from reboot_safety_check.cli import main
from reboot_safety_check.core import DkmsEntry, Finding, Report


def _fake_report(has_failures=False, has_warnings=False):
    findings = [Finding("info", "all good")]
    if has_warnings:
        findings.append(Finding("warn", "something to check"))
    if has_failures:
        findings.append(Finding("fail", "something broken"))

    class R(Report):
        pass

    report = R(
        running_kernel="6.8.0-51-generic",
        installed_kernels=["6.8.0-51-generic"],
        dkms_entries=[DkmsEntry("nvidia", "1.0", "6.8.0-51-generic", "installed")],
        findings=findings,
    )
    return report


def test_cli_clean_system_returns_0(monkeypatch, capsys):
    monkeypatch.setattr("reboot_safety_check.cli.collect_and_evaluate", lambda: _fake_report())
    rc = main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "looks safe to reboot" in out


def test_cli_warnings_return_1(monkeypatch, capsys):
    monkeypatch.setattr(
        "reboot_safety_check.cli.collect_and_evaluate", lambda: _fake_report(has_warnings=True)
    )
    rc = main([])
    assert rc == 1
    assert "review the WARN" in capsys.readouterr().out


def test_cli_failures_return_2(monkeypatch, capsys):
    monkeypatch.setattr(
        "reboot_safety_check.cli.collect_and_evaluate",
        lambda: _fake_report(has_failures=True, has_warnings=True),
    )
    rc = main([])
    assert rc == 2
    assert "NOT SAFE" in capsys.readouterr().out


def test_cli_json_output(monkeypatch, capsys):
    monkeypatch.setattr("reboot_safety_check.cli.collect_and_evaluate", lambda: _fake_report())
    rc = main(["--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["running_kernel"] == "6.8.0-51-generic"
    assert out["has_failures"] is False
