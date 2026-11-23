#!/usr/bin/env python3
"""build-matrix-scan.py -- scan a set of RKE2 releases' fleet lists by
component, each component exactly once per tag it needs, then reconstruct
each release's own batch report and every CVE's fix tag from that single
sweep.

Called by scan-matrix.sh, one directory per release, each already holding:
  <dir>/release.txt            -- the literal RKE2 release tag
  <dir>/fleet.txt               -- that release's own fleet list (preferred), or
  <dir>/fleet.txt.remote-url    -- a URL to a bare image list, when
                                    gen-rke2-vexscan failed for this release

Writes <dir>/scan.json for every release, in the same batch shape scan.sh's
own --release mode would have produced scanning it alone, plus a shared
reports/releases/fix_info.json.

The approach: for every component (image repo) pinned by any release in the
matrix, resolve its full published tag history (./check-latest-tags) and scan
the entire range from the *oldest* tag any release currently pins to that
component's own *latest* published tag, inclusive -- once. Every release's
own current pin falls inside its own component's range by construction, so
this single sweep replaces what used to be three separate passes (scan
current tags, scan latest tags, binary-search for each CVE's fix point):
there's nothing left to search for afterward, every CVE's fix tag is read
straight off the already-scanned range by walking forward until it
disappears. Simpler, and -- for a matrix where current pins are spread across
most of a component's own history, which is the common case here -- not
meaningfully more expensive than the binary search it replaces, since that
search ended up probing nearly the whole range anyway.

Python 3.8+, standard library only, matching the rest of this project.
"""

import json
import os
import subprocess
import sys
import urllib.request

VEXHUB = "https://github.com/rancher/vexhub"
PREFER_VENDOR = "suse"
SEVERITY = "CRITICAL,HIGH"
WORK_DIR = "reports/releases"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXCULPATORY = ("not_affected", "fixed")


def read_lines(dir_path):
    """Return this release's fleet-list lines as (ref, rest) pairs, in file
    order. rest is "" for a bare reference with no assertion."""
    fleet_path = os.path.join(dir_path, "fleet.txt")
    remote_url_path = os.path.join(dir_path, "fleet.txt.remote-url")

    if os.path.isfile(fleet_path) and os.path.getsize(fleet_path) > 0:
        with open(fleet_path, encoding="utf-8") as fh:
            raw = fh.read()
    elif os.path.isfile(remote_url_path):
        with open(remote_url_path, encoding="utf-8") as fh:
            url = fh.read().strip()
        print(f"  fetching bare image list for {dir_path}: {url}")
        with urllib.request.urlopen(url) as resp:
            raw = resp.read().decode("utf-8")
    else:
        print(f"WARNING: no fleet.txt or fleet.txt.remote-url in {dir_path}; skipping", file=sys.stderr)
        return []

    pairs = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        ref = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        pairs.append((ref, rest))
    return pairs


def has_fix(finding):
    if finding.get("fixed_version"):
        return True
    return bool(finding.get("fixed_versions"))


def is_affected(finding):
    if finding.get("status") not in ("linked", "reachable"):
        return False
    vex = finding.get("vex") or {}
    return vex.get("status") not in EXCULPATORY


def affected_cve_ids(result):
    return {
        f.get("id") or f.get("cve")
        for f in (result.get("findings") or [])
        if is_affected(f) and (f.get("id") or f.get("cve"))
    }


def filter_fixed_only(doc):
    """Mirror scan.sh's own post-scan fixed-only filter exactly, so matrix
    output is identical in shape/content to what scan.sh --release would
    have produced for the same release on its own."""
    for result in doc.get("results") or []:
        if result:
            result["findings"] = [f for f in (result.get("findings") or []) if has_fix(f)]


def run_vexscan(batch_file, out_file):
    args = [
        "vexscan",
        "--images-from", batch_file,
        "--all", "--triage",
        "--vexhub", VEXHUB,
        "--prefer-vendor", PREFER_VENDOR,
        "--severity", SEVERITY,
        "--format", "json",
    ]
    print(f"  running: {' '.join(args)} > {out_file}")
    with open(out_file, "w", encoding="utf-8") as out:
        proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, text=True)
    # Batch mode exits 1 whenever any image in the batch could not be pulled
    # or was scanned incompletely -- the JSON is still written, with those
    # images recorded under "failures" rather than "results" (see vexscan's
    # own docs: exit 1 means "look at what's incomplete", not "nothing ran").
    # scan.sh itself only checks the output file is non-empty, not the exit
    # code, for the same reason. A *missing/empty* file is the real failure.
    if not os.path.isfile(out_file) or os.path.getsize(out_file) == 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"vexscan produced no output for {batch_file} (exit {proc.returncode})")
    if proc.returncode != 0:
        print(f"  (vexscan exited {proc.returncode}: some image(s) in this batch were not scanned cleanly -- see failures in the output)")


def repo_of(ref):
    return ref.rsplit(":", 1)[0]


def write_and_scan(pairs_by_ref, label):
    """pairs_by_ref: {ref: rest}. One flat batch, one vexscan call -- safe
    because every ref here is constructed from a distinct (repo, tag) pair,
    so no ref ever repeats with a different assertion the way the old
    cross-release dedup had to guard against. Returns {ref: result}."""
    if not pairs_by_ref:
        return {}
    batch_file = os.path.join(WORK_DIR, f"_{label}.txt")
    with open(batch_file, "w", encoding="utf-8") as fh:
        for ref, rest in pairs_by_ref.items():
            fh.write(f"{ref} {rest}\n" if rest else f"{ref}\n")
    scan_file = os.path.join(WORK_DIR, f"_{label}.scan.json")
    print(f"--- {label}: {len(pairs_by_ref)} image(s) ---")
    run_vexscan(batch_file, scan_file)
    with open(scan_file, encoding="utf-8") as fh:
        doc = json.load(fh)
    return {r["target"]: r for r in (doc.get("results") or []) if r and r.get("target")}


def main():
    dirs = sys.argv[1:]
    if not dirs:
        print("Usage: build-matrix-scan.py <release-dir> [<release-dir> ...]", file=sys.stderr)
        return 1

    release_lines = {d: read_lines(d) for d in dirs}
    os.makedirs(WORK_DIR, exist_ok=True)

    rest_by_ref = {}
    for pairs in release_lines.values():
        for ref, rest in pairs:
            rest_by_ref.setdefault(ref, rest)
    all_current_refs = sorted(rest_by_ref)

    # --- Resolve each component's full tag history ---------------------
    #
    # ./check-latest-tags, unmodified in its own contract, extended to also
    # return the full tag list it already fetches (all_tags) instead of
    # keeping only the latest one. One entry per currently-pinned ref.
    print("=== Resolving component tag histories ===")
    refs_file = os.path.join(WORK_DIR, "_all-images.txt")
    with open(refs_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(all_current_refs) + "\n")
    tags_file = os.path.join(WORK_DIR, "_tags.json")
    proc = subprocess.run(
        [os.path.join(SCRIPT_DIR, "check-latest-tags"), refs_file, "-o", tags_file],
        stderr=subprocess.PIPE, text=True,
    )
    tag_entries = []
    if proc.returncode == 0 and os.path.isfile(tags_file):
        with open(tags_file, encoding="utf-8") as fh:
            tag_entries = json.load(fh)
    else:
        print(f"WARNING: check-latest-tags failed; 'fixes in' info will be unavailable this run\n{proc.stderr}", file=sys.stderr)

    # --- Build one exhaustive scan list per component -------------------
    #
    # For each component (image repo), the range from the oldest tag any
    # release currently pins to the component's own latest published tag,
    # inclusive -- scanned once. This single list replaces the old separate
    # "scan current tags" + "scan latest tags" + "binary-search rounds"
    # passes entirely: every release's current pin falls inside its own
    # component's range by construction, and every CVE's fix tag can be read
    # straight off the already-scanned range afterward, with no more
    # scanning needed to find it.
    repo_all_tags = {}
    repo_latest_tag = {}
    repo_current_tags = {}
    for e in tag_entries:
        repo = repo_of(e["image"])
        repo_current_tags.setdefault(repo, set()).add(e["current_tag"])
        if e.get("all_tags"):
            repo_all_tags.setdefault(repo, e["all_tags"])
        if e.get("latest_tag"):
            repo_latest_tag.setdefault(repo, e["latest_tag"])

    scan_pairs = {}       # ref -> rest, everything that needs scanning
    repo_range = {}       # repo -> ordered list of tags actually covered, or None
    for repo, current_tags in repo_current_tags.items():
        all_tags = repo_all_tags.get(repo)
        latest_tag = repo_latest_tag.get(repo)
        rest = next((rest_by_ref[f"{repo}:{t}"] for t in current_tags if f"{repo}:{t}" in rest_by_ref), "")

        tags_range = None
        if all_tags and latest_tag:
            try:
                idx_oldest = min(all_tags.index(t) for t in current_tags)
                idx_latest = all_tags.index(latest_tag)
                tags_range = all_tags[idx_oldest: idx_latest + 1]
            except ValueError:
                tags_range = None  # a current tag or latest isn't in the published list

        repo_range[repo] = tags_range
        tags_to_scan = tags_range if tags_range else current_tags
        for t in tags_to_scan:
            scan_pairs.setdefault(f"{repo}:{t}", rest)

    print(f"  {len(repo_current_tags)} component(s), {len(all_current_refs)} pinned reference(s), "
          f"{len(scan_pairs)} image(s) to scan (exhaustive per-component ranges)")

    results = write_and_scan(scan_pairs, "sweep")
    affected_by_ref = {ref: affected_cve_ids(r) for ref, r in results.items()}

    # --- Reconstruct each release's own report --------------------------
    print("=== Reconstructing per-release reports ===")
    for d, pairs in release_lines.items():
        res_list, fail_list = [], []
        for ref, _rest in pairs:
            if ref in results:
                res_list.append(results[ref])
            else:
                fail_list.append({"target": ref, "error": "not scanned (image pull/scan failed)"})

        doc = {
            "schema_version": 1,
            "mode": "batch",
            "targets": len(res_list) + len(fail_list),
            "results": res_list,
            "failures": fail_list,
        }
        filter_fixed_only(doc)

        out_path = os.path.join(d, "scan.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        print(f"  {d}: {len(res_list)} scanned, {len(fail_list)} failed -> {out_path}")

    # --- Which tag fixes each CVE, read straight off the sweep ----------
    #
    # For every CVE affecting a current tag, walk forward through that
    # component's already-scanned range and take the first tag where it's
    # gone. A tag that failed to scan is skipped rather than treated as
    # "still affected", so one missing historical build doesn't block
    # finding a later one that did fix it.
    print("=== Computing fix tags from the sweep ===")
    fix_info = {}
    for repo, current_tags in repo_current_tags.items():
        latest_tag = repo_latest_tag.get(repo)
        tags_range = repo_range.get(repo)
        for current_tag in current_tags:
            ref = f"{repo}:{current_tag}"
            if not latest_tag:
                status = "UNKNOWN"
            elif current_tag == latest_tag:
                status = "UP_TO_DATE"
            else:
                status = "NEEDS_UPDATE"

            entry = {
                "current_tag": current_tag,
                "latest_tag": latest_tag,
                "status": status,
                "fixes": {},
                "latest_checked": False,
            }

            if status == "NEEDS_UPDATE" and tags_range:
                current_ids = affected_by_ref.get(ref, set())
                idx_current = tags_range.index(current_tag)
                for cve in current_ids:
                    for later_tag in tags_range[idx_current + 1:]:
                        later_ids = affected_by_ref.get(f"{repo}:{later_tag}")
                        if later_ids is None:
                            continue  # that tag failed to scan; try the next one
                        if cve not in later_ids:
                            entry["fixes"][cve] = later_tag
                            break
                entry["latest_checked"] = True

            fix_info[ref] = entry

    fix_info_path = os.path.join(WORK_DIR, "fix_info.json")
    with open(fix_info_path, "w", encoding="utf-8") as fh:
        json.dump(fix_info, fh)
    print(f"  wrote {fix_info_path}")

    return 0



if __name__ == "__main__":
    sys.exit(main())
