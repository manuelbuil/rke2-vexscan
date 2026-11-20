#!/bin/bash

# scan-matrix.sh -- scan a list of RKE2 release tags, sharing one vexscan
# invocation across every release instead of running scan.sh once per tag.
#
# Usage: ./scan-matrix.sh < releases.txt
#        ./list-releases 1.36 1.37 | ./scan-matrix.sh
#        ./scan-matrix.sh v1.37.2+rke2r1 v1.36.6+rke2r1
#
# Reads tags from argv if given, otherwise from stdin (one per line, blank
# lines and #-comments skipped).
#
# Why not just call scan.sh once per release: adjacent RKE2 patches, and even
# adjacent minors, routinely pin the exact same image -- coredns v1.14.7 is
# the real example that prompted this, shared across four 1.36/1.37 patches
# at once. Scanning it once per release re-pulls the same image and re-queries
# OSV for it every time. Instead this script only uses gen-rke2-vexscan
# per-release (cheap: registry-blob reads it already caches under
# ~/.cache/rke2-vexscan/), then hands every release's fleet list to
# build-matrix-scan.py, which de-duplicates identical (image, assertion)
# lines across the whole matrix and scans the remainder in as few vexscan
# invocations as it can.
#
# Output layout, one directory per release:
#   reports/releases/<slug>/fleet.txt    -- this release's own fleet list
#   reports/releases/<slug>/release.txt  -- the literal tag (undoes the slug)
#   reports/releases/<slug>/scan.json    -- this release's own batch report,
#                                           reconstructed from the shared scan

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out_root="reports/releases"

slug_of() {
    # v1.37.0+rke2r1 -> v1.37.0.rke2r1 (same substitution scan-report.yml
    # already uses for release scan IDs)
    echo "${1//+/.}"
}

read_tags() {
    if [[ $# -gt 0 ]]; then
        printf '%s\n' "$@"
    else
        cat
    fi
}

mkdir -p "$out_root"

tags=()
while IFS= read -r line; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs)" # trim whitespace
    [[ -z "$line" ]] && continue
    tags+=("$line")
done < <(read_tags "$@")

if [[ ${#tags[@]} -eq 0 ]]; then
    echo "No release tags given (argv or stdin)." >&2
    exit 1
fi

echo "=== Generating fleet lists for ${#tags[@]} release(s) ==="
dirs=()
failed_gen=0
for tag in "${tags[@]}"; do
    slug=$(slug_of "$tag")
    dir="$out_root/$slug"
    mkdir -p "$dir"
    echo "$tag" > "$dir/release.txt"

    echo "--- $tag -> $dir/fleet.txt ---"
    if "$script_dir/gen-rke2-vexscan" "$tag" -o "$dir/fleet.txt" --lists default; then
        dirs+=("$dir")
    else
        echo "WARNING: gen-rke2-vexscan failed for $tag; it will be scanned on its own, without entrypoint=/roots= assertions, and will not share the de-duplicated batch" >&2
        # Fall back to the bare published image list for this one release, so
        # one failure doesn't drop it from the matrix entirely.
        echo "https://github.com/rancher/rke2/releases/download/${tag//+/%2B}/rke2-images.linux-amd64.txt" \
            > "$dir/fleet.txt.remote-url"
        failed_gen=$((failed_gen + 1))
        dirs+=("$dir")
    fi
done

echo
echo "=== Scanning (shared, de-duplicated across the matrix) ==="
python3 "$script_dir/build-matrix-scan.py" "${dirs[@]}"
status=$?

echo
if [[ $status -eq 0 ]]; then
    echo "scan-matrix: ${#tags[@]} release(s) processed ($failed_gen fleet-list fallback(s))"
else
    echo "scan-matrix: FAILED (see above)" >&2
fi
exit $status
