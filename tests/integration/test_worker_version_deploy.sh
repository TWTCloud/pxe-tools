#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
fixture=$(mktemp -d /var/tmp/pxe-version-deploy-XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/assets"
cat > "$fixture/wrangler" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CALL_LOG"
if [[ "${FAIL_UPLOAD:-0}" == 1 && "$1 $2" == 'versions upload' ]]; then exit 1; fi
if [[ "$1 $2" == 'versions deploy' && "${DEPLOY_FAILURES:-0}" -gt 0 ]]; then
    count=$(cat "$CALL_LOG.deploy" 2>/dev/null || echo 0)
    echo $((count + 1)) > "$CALL_LOG.deploy"
    if [[ "$count" -lt "$DEPLOY_FAILURES" ]]; then echo "${DEPLOY_ERROR:-code: 100146}" >&2; exit 1; fi
fi
MOCK
chmod +x "$fixture/wrangler"
export CALL_LOG="$fixture/log" GITHUB_RUN_ID=123456 GITHUB_RUN_ATTEMPT=1
cd "$root"
bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets"
test "$(wc -l < "$CALL_LOG" | tr -d ' ')" = 2
grep -Fx "versions upload --config packaging/cloudflare/wrangler.jsonc --assets $fixture/assets --tag apt-123456-1" "$CALL_LOG" >/dev/null
grep -Fx 'versions deploy --config packaging/cloudflare/wrangler.jsonc --version-tag apt-123456-1@100% --yes' "$CALL_LOG" >/dev/null
: > "$CALL_LOG"
if FAIL_UPLOAD=1 bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets"; then
    echo 'Failed upload unexpectedly deployed a version' >&2; exit 1
fi
test "$(wc -l < "$CALL_LOG" | tr -d ' ')" = 1
: > "$CALL_LOG"
if GITHUB_RUN_ID=bad bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets"; then
    echo 'Invalid run identifier unexpectedly accepted' >&2; exit 1
fi
test ! -s "$CALL_LOG"
export DEPLOY_RETRY_SECONDS=0
: > "$CALL_LOG"; rm -f "$CALL_LOG.deploy"
DEPLOY_FAILURES=2 bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets" >/dev/null 2>&1
test "$(grep -c '^versions deploy' "$CALL_LOG")" = 3
: > "$CALL_LOG"; rm -f "$CALL_LOG.deploy"
if DEPLOY_FAILURES=9 bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets" >/dev/null 2>&1; then
    echo 'Persistent 100146 unexpectedly succeeded' >&2; exit 1
fi
test "$(grep -c '^versions deploy' "$CALL_LOG")" = 5
: > "$CALL_LOG"; rm -f "$CALL_LOG.deploy"
if DEPLOY_FAILURES=9 DEPLOY_ERROR='code: 10000' bash packaging/ci/deploy-worker-version.sh "$fixture/wrangler" "$fixture/assets" >/dev/null 2>&1; then
    echo 'Unrelated deploy error unexpectedly succeeded' >&2; exit 1
fi
test "$(grep -c '^versions deploy' "$CALL_LOG")" = 1
echo 'Version upload/deploy ordering and failures verified without Cloudflare.'
