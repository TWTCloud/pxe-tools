#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Exercise an explicit same-primary subkey transition with disposable APT state.
set -euo pipefail

[[ "${PXE_APT_ROTATION_FIXTURE:-}" == 1 ]] || {
  echo 'Set PXE_APT_ROTATION_FIXTURE=1 in a disposable test environment.' >&2
  exit 1
}
root=$(cd "$(dirname "$0")/../.." && pwd)
fixture=$(mktemp -d /tmp/pxe-rotation-apt-XXXXXXXX)
home="$fixture/gnupg"
mkdir -m 0700 "$home"
cleanup() {
  gpgconf --homedir "$home" --kill gpg-agent >/dev/null 2>&1 || true
  python3 - "$fixture" <<'PY'
import shutil, sys
shutil.rmtree(sys.argv[1])
PY
}
trap cleanup EXIT

passfile="$fixture/passphrase"
printf '%s\n' 'temporary-fixture-passphrase' > "$passfile"
chmod 0600 "$passfile"
gpg_base=(gpg --homedir "$home" --batch --no-tty --pinentry-mode loopback --passphrase-file "$passfile")
"${gpg_base[@]}" --quick-generate-key 'APT rotation fixture <apt-rotation@example.invalid>' ed25519 cert 1d >/dev/null 2>&1
primary=$("${gpg_base[@]}" --with-colons --with-fingerprint --list-secret-keys | awk -F: '$1=="fpr" {print $10; exit}')
"${gpg_base[@]}" --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
old_signer=$("${gpg_base[@]}" --with-colons --with-fingerprint --with-subkey-fingerprint --list-secret-keys | awk -F: '$1=="fpr" {n++; if(n==2) {print $10; exit}}')
"${gpg_base[@]}" --export "$primary" > "$fixture/old-public.gpg"
"${gpg_base[@]}" --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
new_signer=$("${gpg_base[@]}" --with-colons --with-fingerprint --with-subkey-fingerprint --list-secret-keys | awk -F: '$1=="fpr" {n++; if(n==3) {print $10; exit}}')
"${gpg_base[@]}" --export "$primary" > "$fixture/new-public.gpg"
[[ -n "$primary" && -n "$old_signer" && -n "$new_signer" && "$old_signer" != "$new_signer" ]]

pkg="$fixture/package"
mkdir -p "$pkg/DEBIAN"
cat > "$pkg/DEBIAN/control" <<'CONTROL'
Package: pxe-tools
Version: 1.0~fixture1
Architecture: amd64
Maintainer: Fixture <fixture@example.invalid>
Description: Synthetic package for APT rotation rehearsal
CONTROL
dpkg-deb --build --root-owner-group "$pkg" "$fixture/old.deb" >/dev/null
builder="$root/packaging/native/build-apt-release-candidate.py"
python3 "$builder" "$fixture/old.deb" "$fixture/old" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$old_signer" --valid-days 1 >/dev/null
sed -i 's/Version: 1.0~fixture1/Version: 1.0~fixture2/' "$pkg/DEBIAN/control"
dpkg-deb --build --root-owner-group "$pkg" "$fixture/new.deb" >/dev/null

# The existing default remains fail-closed when the previous signer differs.
if python3 "$builder" "$fixture/new.deb" "$fixture/no-transition" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$new_signer" --previous "$fixture/old" > "$fixture/default.log" 2>&1; then
  echo 'Unexpected acceptance without explicit transition identities' >&2; exit 1
fi
test ! -e "$fixture/no-transition"

# Explicit transition pins the old signer and primary, retaining old objects.
args=(--gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$new_signer" --previous "$fixture/old" --valid-days 1
      --previous-signing-fingerprint "$old_signer" --previous-primary-fingerprint "$primary")
python3 "$builder" "$fixture/new.deb" "$fixture/new" "${args[@]}" >/dev/null
old_index="$fixture/old/dists/stable/main/binary-amd64/Packages.gz"
old_sha256=$(sha256sum "$old_index" | awk '{print $1}')
old_sha512=$(sha512sum "$old_index" | awk '{print $1}')
cmp "$fixture/old/dists/stable/main/binary-amd64/by-hash/SHA256/$old_sha256" "$fixture/new/dists/stable/main/binary-amd64/by-hash/SHA256/$old_sha256"
cmp "$fixture/old/dists/stable/main/binary-amd64/by-hash/SHA512/$old_sha512" "$fixture/new/dists/stable/main/binary-amd64/by-hash/SHA512/$old_sha512"
old_package=$(find "$fixture/old/pool" -name '*.deb' -print -quit)
cmp "$old_package" "$fixture/new/pool/main/p/pxe-tools/$(basename "$old_package")"
# Recover genuine signed fixture snapshots and exercise failure/retry ordering.
PXE_ROTATION_FIXTURE_DIR="$fixture" PXE_ROTATION_PRIMARY="$primary" \
  PXE_ROTATION_OLD_SIGNER="$old_signer" PXE_ROTATION_NEW_SIGNER="$new_signer" \
  python3 "$root/tests/integration/test_apt_snapshot_recovery_fixture.py" -v

# CI transition uses only the new secret subkey; the old certificate is public.
"${gpg_base[@]}" --armor --export-secret-subkeys "${new_signer}!" > "$fixture/new-secret.asc"
export APT_SIGNING_KEY="$(cat "$fixture/new-secret.asc")"
export APT_SIGNING_PASSPHRASE='temporary-fixture-passphrase'
ci_signer="$root/packaging/native/ci-sign-apt-candidate.py"
ci_args=(--primary-fingerprint "$primary" --signing-fingerprint "$new_signer" --previous "$fixture/old"
         --transition-previous-signing-fingerprint "$old_signer" --transition-previous-public-key "$fixture/old-public.gpg")
python3 "$ci_signer" "$fixture/new.deb" "$fixture/ci-new" "${ci_args[@]}" --public-key-output "$fixture/ci-public.gpg" >/dev/null
gpgv --keyring "$fixture/ci-public.gpg" "$fixture/old/dists/stable/InRelease" >/dev/null 2>&1
gpgv --keyring "$fixture/ci-public.gpg" "$fixture/ci-new/dists/stable/InRelease" >/dev/null 2>&1
if python3 "$ci_signer" "$fixture/new.deb" "$fixture/ci-wrong-old" --primary-fingerprint "$primary" --signing-fingerprint "$new_signer" --previous "$fixture/old" --transition-previous-signing-fingerprint "$(printf '%040d' 0)" --transition-previous-public-key "$fixture/old-public.gpg" > "$fixture/ci-wrong-old.log" 2>&1; then
  echo 'CI signer unexpectedly accepted the wrong previous signer' >&2; exit 1
fi
test ! -e "$fixture/ci-wrong-old"
"${gpg_base[@]}" --export-secret-keys "$primary" > "$fixture/secret-key.gpg"
if python3 "$ci_signer" "$fixture/new.deb" "$fixture/ci-secret" --primary-fingerprint "$primary" --signing-fingerprint "$new_signer" --previous "$fixture/old" --transition-previous-signing-fingerprint "$old_signer" --transition-previous-public-key "$fixture/secret-key.gpg" > "$fixture/ci-secret.log" 2>&1; then
  echo 'CI signer unexpectedly accepted private material as a previous certificate' >&2; exit 1
fi
test ! -e "$fixture/ci-secret"
unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE

# Wrong identities and incomplete transitions must not publish an output tree.
if python3 "$builder" "$fixture/new.deb" "$fixture/wrong-old" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$new_signer" --previous "$fixture/old" --previous-signing-fingerprint "$new_signer" --previous-primary-fingerprint "$primary" > "$fixture/wrong-old.log" 2>&1; then
  echo 'Unexpected acceptance of the wrong previous signer' >&2; exit 1
fi
test ! -e "$fixture/wrong-old"
if python3 "$builder" "$fixture/new.deb" "$fixture/wrong-primary" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$new_signer" --previous "$fixture/old" --previous-signing-fingerprint "$old_signer" --previous-primary-fingerprint "$(printf '%040d' 0)" > "$fixture/wrong-primary.log" 2>&1; then
  echo 'Unexpected acceptance of the wrong primary' >&2; exit 1
fi
test ! -e "$fixture/wrong-primary"
if python3 "$builder" "$fixture/new.deb" "$fixture/incomplete" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$new_signer" --previous "$fixture/old" --previous-signing-fingerprint "$old_signer" > "$fixture/incomplete.log" 2>&1; then
  echo 'Unexpected acceptance of an incomplete transition' >&2; exit 1
fi
test ! -e "$fixture/incomplete"

# A correctly signed previous release cannot authorize a new signer from a
# different primary, even if that signer's fingerprint was explicitly supplied.
"${gpg_base[@]}" --quick-generate-key 'Other fixture <other-rotation@example.invalid>' ed25519 sign 1d >/dev/null 2>&1
other_signer=$("${gpg_base[@]}" --with-colons --with-fingerprint --list-secret-keys 'other-rotation@example.invalid' | awk -F: '$1=="fpr" {print $10; exit}')
[[ -n "$other_signer" && "$other_signer" != "$primary" ]]
if python3 "$builder" "$fixture/new.deb" "$fixture/wrong-new-primary" --gnupg-home "$home" --passphrase-file "$passfile" --fingerprint "$other_signer" --previous "$fixture/old" --previous-signing-fingerprint "$old_signer" --previous-primary-fingerprint "$primary" > "$fixture/wrong-new-primary.log" 2>&1; then
  echo 'Unexpected acceptance of a new signer from another primary' >&2; exit 1
fi
test ! -e "$fixture/wrong-new-primary"

# A separate APT state is used for every attempt; no system sources are changed.
mkdir -p "$fixture/client/parts"
touch "$fixture/client/status"
printf 'deb [signed-by=%s/old-public.gpg] file:%s/old stable main\n' "$fixture" "$fixture" > "$fixture/client/old.list"
printf 'deb [signed-by=%s/old-public.gpg] file:%s/new stable main\n' "$fixture" "$fixture" > "$fixture/client/stale.list"
printf 'deb [signed-by=%s/new-public.gpg] file:%s/new stable main\n' "$fixture" "$fixture" > "$fixture/client/new.list"
apt_check() {
  local label="$1" source="$2" lists="$fixture/client/lists-$1"
  mkdir -p "$lists/partial"
  apt-get -o "APT::Sandbox::User=$(id -un)" -o "Dir::Etc::sourcelist=$source" -o "Dir::Etc::sourceparts=$fixture/client/parts" \
    -o "Dir::State::lists=$lists" -o "Dir::State::status=$fixture/client/status" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
    -o APT::Update::Error-Mode=any update > "$fixture/client/$label.log" 2>&1
}
apt_check old "$fixture/client/old.list"
if apt_check stale "$fixture/client/stale.list"; then
  echo 'Old client unexpectedly accepted the new signing subkey' >&2; exit 1
fi
grep -q 'NO_PUBKEY' "$fixture/client/stale.log"
apt_check updated "$fixture/client/new.list"
apt-get -o "APT::Sandbox::User=$(id -un)" -o "Dir::Etc::sourcelist=$fixture/client/new.list" \
  -o "Dir::Etc::sourceparts=$fixture/client/parts" -o "Dir::State::lists=$fixture/client/lists-updated" \
  -o "Dir::State::status=$fixture/client/status" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
  --simulate install pxe-tools > "$fixture/client/install-simulation.log" 2>&1
grep -q '^Inst pxe-tools (1.0~fixture2 ' "$fixture/client/install-simulation.log"
# The updated certificate continues to authenticate the old release.
gpgv --keyring "$fixture/new-public.gpg" "$fixture/old/dists/stable/InRelease" >/dev/null 2>&1
echo 'OK disposable old/new signing subkeys, immutable objects and isolated APT client'
