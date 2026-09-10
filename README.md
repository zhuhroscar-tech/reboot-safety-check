# reboot-safety-check

Warns you about DKMS/kernel-module problems for a kernel you've just
installed but haven't booted into yet — **before** you reboot into it.

## The problem

On distros that use DKMS (out-of-tree kernel modules: proprietary NVIDIA/AMD
GPU drivers, Wi-Fi drivers like `rtl8812au`/`rtl8852au`, VirtualBox host
modules, ZFS, ...), installing a new kernel package does **not** guarantee
the DKMS module was rebuilt successfully for it. When the build silently
fails — missing kernel headers, a compiler mismatch, a kernel API the module
hasn't caught up with — the system boots into the new kernel with that
module simply missing: no GPU driver, no Wi-Fi, no VirtualBox. This is a
recurring, well-documented failure mode across Arch, Ubuntu, Fedora and
Debian forums/bug trackers (DKMS builds failing after kernel updates,
`dkms status` showing `added` instead of `installed`, NVIDIA/rtl88xx modules
specifically) — and by the time you notice, you're already at a broken
desktop or a dropped Wi-Fi connection.

## What this does

```
$ reboot-safety-check
Running kernel:    6.8.0-51-generic
Installed kernels: 6.8.0-51-generic, 6.9.0-1-generic
DKMS modules seen: nvidia

[FAIL] DKMS module 'nvidia' for kernel 6.9.0-1-generic is only 'added', not
       fully installed. This module likely will not load after rebooting
       into 6.9.0-1-generic.

Result: NOT SAFE to reboot yet -- see FAIL lines above.
```

It cross-references every kernel version you have installed (via
`/lib/modules/*`) against `dkms status`, flags any DKMS module that isn't
fully `installed` for an installed-but-not-yet-booted kernel, checks whether
matching kernel headers are present (a common root cause of build failure),
and — when Secure Boot is enabled — actually verifies module signing state
instead of just telling you to check manually:

- If Secure Boot is on and **no Machine Owner Key is enrolled at all**
  (`mokutil --list-enrolled` reports zero), that's flagged as a **FAIL**:
  a DKMS build can succeed and still be silently refused at load time with
  no enrolled key to trust it.
- If keys are enrolled, each not-yet-booted kernel's DKMS module is spot
  checked via `modinfo -k KERNEL MODULE` for a `signer:`/`sig_id:` field;
  a module built but genuinely unsigned is flagged as a **FAIL** naming the
  exact module and kernel, not a generic reminder.

This closes the exact gap behind "the build succeeded, the module still
won't load" reports common with NVIDIA/AMD DKMS drivers under Secure Boot.

**Read-only.** It never runs `dkms install`, never calls a package manager,
and never reboots, signs, or enrolls anything — it only reads `dkms status`,
`/lib/modules`, `uname -r`, package-manager query commands (`dpkg-query -W`,
`rpm -q`), `mokutil --sb-state`, `mokutil --list-enrolled`, and
`modinfo -k`.

## Install

Requires Python 3.9+. `dkms` itself is optional — if it's not installed,
the tool just reports "no DKMS modules registered" (nothing to check).

```bash
pip install --user reboot-safety-check   # once published to PyPI
```

Or grab the standalone `.pyz` from a GitHub Release (no pip/venv needed):

```bash
curl -LO https://github.com/zhuhroscar-tech/reboot-safety-check/releases/download/v0.1.0/reboot-safety-check.pyz
python3 reboot-safety-check.pyz --help
```

Or from source:

```bash
git clone https://github.com/zhuhroscar-tech/reboot-safety-check.git
cd reboot-safety-check
pip install --user .
```

## Usage

Run it any time after `apt upgrade` / `dnf upgrade` / `pacman -Syu` installs
a new kernel, before you reboot:

```bash
reboot-safety-check          # human-readable report
reboot-safety-check --json   # machine-readable JSON
```

Exit codes: `0` safe to reboot, `1` warnings worth reviewing, `2` a real
failure was found (a DKMS module will very likely be missing after reboot).

## Uninstall

```bash
pip uninstall reboot-safety-check
```

No config files, no persistent state, no cache — it's a stateless read-only
check.

## Privacy & permissions

No network access, no telemetry. Reads `/lib/modules`, runs `dkms status`,
`uname -r`, `dpkg-query`/`rpm -q`, `mokutil --sb-state`, `mokutil
--list-enrolled`, and `modinfo -k` — all read-only, no root required for
any of these on a standard install (though `dkms status` output can be
more complete when run as root on some distros).

## Distro / architecture support

Pure Python (stdlib only). Works on any Linux distribution and architecture
with Python 3.9+; `dkms`, `dpkg`/`rpm`, `mokutil`, and `modinfo` are used
opportunistically when present and gracefully skipped when absent (their
absence is reported as "unknown", never treated as an error).

## Reproducible build & test

```bash
git clone https://github.com/zhuhroscar-tech/reboot-safety-check.git
cd reboot-safety-check
python3 -m venv .venv && . .venv/bin/activate
pip install -e . pytest
pytest -v
python -m build
python -m zipapp build/pyz-deps -m "reboot_safety_check.cli:main" -o dist/reboot-safety-check.pyz
```

CI (`.github/workflows/ci.yml`) runs the same steps on real Ubuntu Linux
GitHub Actions runners for every push/PR, including a smoke test of the
installed console script and the standalone `.pyz` against the runner's
actual kernel/module state.

## License

MIT — see [LICENSE](LICENSE).
