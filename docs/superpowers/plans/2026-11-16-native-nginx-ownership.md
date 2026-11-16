# Native nginx dependency reconciliation implementation plan

> Execute this bounded plan with the existing PR checks; no local builds/tests.

**Goal:** Prevent the generic nginx dependency from retaining80 when ownership
is proven, while preserving preexisting services and intentional states.

**Architecture:** A root-only native reconciliation helper with positive APT/dpkg
provenance and complete stock configuration checks, called by the core postinst.
No global service policy or dependency ordering assumptions.

**Tech stack:** Python3 standard library, Debian maintainer scripts, systemd.

**Spec:** `docs/superpowers/specs/2026-11-16-native-nginx-ownership-design.md`.

- [x] Add behavior regressions in `tests/unit/test_native_nginx_ownership.py` and
  register them in `tests/ci/run-application-tests.sh`. Commit/push draft PR and
  receive the expected failure from the existing application CI.
- [x] Add `packaging/native/reconcile-nginx.py`; keep external command boundaries
  injectable for fixtures, fail closed for missing provenance/custom config.
- [x] Package and call the helper from `build-local-package.py` postinst before
  lifecycle configuration. Explain the explicit stock repair and rollback in
  native documentation; preserve no-interaction upgrades and all PXE states.
- [ ] Receive exact-head existing PR checks, independent review and required
  branch/rule checks; integrate base updates normally and merge only if eligible.
- [ ] Report SHA/check evidence, native-systemd receipt limitation and the separate
  candidate/publication lot. Do not change approved beta7 manifest or publish.

## Evidence and rulings

- Baseline `main@1a9143d0`; no local builds/tests (explicit task constraint).
- Regression RED: commit `c5931859`, application run `43851475273`, actual
  assertion that APT-installed generic nginx still retained the boot listener.
- Existing PR checks run in hosted disposable fixtures; no dedicated private
  CI exists for this public history. The historical private Docker checks are
  not reused as evidence. No workflow or publication settings changed.
- Independent review found a first-setup collision between the initial journal
  location and secure TFTP preparation. Keep ownership metadata in the separate
  `/var/lib/pxe-tools-nginx-ownership` tree, and exercise the real secure preparer
  in the maintainer-script regression; do not relax its existing-path guard.
- Open APT records require actual dpkg/APT ancestry rather than an arbitrary
  recent-time cutoff; this also allows a slow initial dependency installation.
