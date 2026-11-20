#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
# Upload and deploy a unique version; domain/route triggers are managed separately.
set -euo pipefail
if [[ "$#" != 2 || ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ || ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,9}$ ]]; then
    echo 'Expected wrangler, assets directory, and valid GitHub run identifiers.' >&2
    exit 1
fi
wrangler="$1"
assets="$2"
if [[ ! -x "$wrangler" || ! -d "$assets" ]]; then
    echo 'Wrangler or verified assets directory is missing.' >&2
    exit 1
fi
tag="apt-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
config=packaging/cloudflare/wrangler.jsonc
"$wrangler" versions upload --config "$config" --assets "$assets" --tag "$tag"
# A version uploaded a moment ago can be briefly unknown to the deploy API
# (code 100146). Retry only that error, never any other failure.
for attempt in 1 2 3 4 5; do
    if output=$("$wrangler" versions deploy --config "$config" --version-tag "$tag@100%" --yes 2>&1); then
        printf '%s\n' "$output"
        exit 0
    fi
    printf '%s\n' "$output" >&2
    [[ "$output" == *"100146"* && "$attempt" -lt 5 ]] || exit 1
    sleep $((attempt * ${DEPLOY_RETRY_SECONDS:-5}))
done
