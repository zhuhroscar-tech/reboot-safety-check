"""Regression checks for modern packaging metadata.

Setuptools 77+ deprecates the legacy TOML table form
``license = { text = "MIT" }`` and the license classifier style for
project metadata. Keep the package on the current SPDX/license-files form so
local builds and release CI stay warning-free.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def test_project_license_uses_spdx_string_form():
    text = _pyproject_text()
    assert 'license = "MIT"' in text
    assert "license = {" not in text
    assert 'license-files = ["LICENSE"]' in text


def test_deprecated_license_classifier_is_not_reintroduced():
    text = _pyproject_text()
    assert "License :: OSI Approved :: MIT License" not in text


def test_setuptools_floor_supports_spdx_license_metadata():
    text = _pyproject_text()
    match = re.search(r'requires = \["setuptools>=(\d+)"', text)
    assert match, "build-system.requires must pin a setuptools floor"
    assert int(match.group(1)) >= 77
