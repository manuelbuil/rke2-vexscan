#!/usr/bin/env python3
"""build-matrix-scan.py -- scan a set of RKE2 releases' fleet lists with as
few vexscan invocations as possible, by de-duplicating identical
(image, assertion) lines across the whole matrix before scanning, then
reconstructing each release's own batch report from the shared result pool.

Called by scan-matrix.sh, one directory per release, each already holding:
  <dir>/release.txt            -- the literal RKE2 release tag
  <dir>/fleet.txt               -- that release's own fleet list (preferred), or
  <dir>/fleet.txt.remote-url    -- a URL to a bare image list, when
                                    gen-rke2-vexscan failed for this release

Writes <dir>/scan.json for every release, in the same batch shape scan.sh's
own --release mode would have produced scanning it alone.

Why not just concatenate every fleet list and scan once: vexscan's own
--images-from refuses a reference named twice when either occurrence carries
an assertion (imagelist.go's parseImageList) -- even if the two assertions
are byte-identical, it never compares them, it just rejects the file. So
lines are only merged when they are *exactly* equal (same ref, same
assertion text); a ref seen with a second, different assertion elsewhere in
the matrix gets its own batch instead of erroring out the whole run.

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


def main():
    dirs = sys.argv[1:]
    if not dirs:
        print("Usage: build-matrix-scan.py <release-dir> [<release-dir> ...]", file=sys.stderr)
        return 1

    release_lines = {}
    for d in dirs:
        release_lines[d] = read_lines(d)

    # variant_order[ref] is the list of distinct "rest" strings seen for that
    # ref, in first-seen order. Its index IS the batch number: every (ref,
    # rest) pair with the same index lands in the same batch, and a batch
    # never contains the same ref twice by construction.
    variant_order = {}

    def variant_index(ref, rest):
        variants = variant_order.setdefault(ref, [])
        if rest not in variants:
            variants.append(rest)
        return variants.index(rest)

    batches = {}  # batch_num -> {ref: rest}
    for d, pairs in release_lines.items():
        for ref, rest in pairs:
            v = variant_index(ref, rest)
            batches.setdefault(v, {})[ref] = rest

    n_batches = len(batches)
    total_lines = sum(len(v) for v in batches.values())
    total_scanned_refs = sum(len(p) for p in release_lines.values())
    print(f"=== {len(dirs)} release(s), {total_scanned_refs} image reference(s) before dedup, "
          f"{total_lines} unique (image, assertion) line(s), {n_batches} batch(es) ===")

    os.makedirs(WORK_DIR, exist_ok=True)
    batch_results = {}   # (batch_num, ref) -> result dict
    batch_failures = {}  # (batch_num, ref) -> error string

    for b, refs in sorted(batches.items()):
        batch_file = os.path.join(WORK_DIR, f"_batch_{b}.txt")
        with open(batch_file, "w", encoding="utf-8") as fh:
            for ref, rest in refs.items():
                fh.write(f"{ref} {rest}\n" if rest else f"{ref}\n")

        scan_file = os.path.join(WORK_DIR, f"_batch_{b}.scan.json")
        print(f"--- batch {b}: {len(refs)} image(s) ---")
        run_vexscan(batch_file, scan_file)

        with open(scan_file, encoding="utf-8") as fh:
            batch_doc = json.load(fh)
        for result in batch_doc.get("results") or []:
            if result and result.get("target"):
                batch_results[(b, result["target"])] = result
        for failure in batch_doc.get("failures") or []:
            if failure and failure.get("target"):
                batch_failures[(b, failure["target"])] = failure.get("error", "unknown error")

    print("=== Reconstructing per-release reports ===")
    for d, pairs in release_lines.items():
        results = []
        failures = []
        for ref, rest in pairs:
            v = variant_order[ref].index(rest)
            if (v, ref) in batch_results:
                results.append(batch_results[(v, ref)])
            elif (v, ref) in batch_failures:
                failures.append({"target": ref, "error": batch_failures[(v, ref)]})
            else:
                failures.append({"target": ref, "error": "not found in any batch output (internal matrix error)"})

        doc = {
            "schema_version": 1,
            "mode": "batch",
            "targets": len(results) + len(failures),
            "results": results,
            "failures": failures,
        }
        filter_fixed_only(doc)

        out_path = os.path.join(d, "scan.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        print(f"  {d}: {len(results)} scanned, {len(failures)} failed -> {out_path}")

    # --- Which tag fixes each CVE -------------------------------------
    #
    # For every component actually scanned above, resolve every tag its build
    # repo has published (./check-latest-tags, unmodified except that it now
    # also returns the full tag list it already fetched instead of keeping
    # only the latest one). A CVE confirmed fixed at the latest tag might
    # already have been fixed several builds earlier -- "latest" is just
    # where the search is guaranteed to succeed, not where it necessarily
    # starts -- so once latest confirms a fix exists, binary-search the
    # published tags between current and latest for the earliest one that
    # actually lacks it, assuming (like scan.sh's own staleness check does)
    # that a fix, once shipped, isn't reintroduced by a later rebuild.
    #
    # One probe scans one image, which reports on every CVE being searched
    # for that component at once, so the search runs in rounds: each round
    # computes the next midpoint for every CVE still narrowing on a given
    # component, batches all distinct (component, midpoint) probes the whole
    # matrix needs that round through the same dedup machinery as the main
    # pass, then narrows every CVE's bounds from the results. A component
    # whose CVEs converge on the same midpoints (the common case -- one
    # rebuild usually fixes several CVEs together) costs one probe for all of
    # them, not one per CVE.
    print("=== Resolving latest available tags ===")
    all_refs = sorted({ref for (_b, ref) in batch_results})
    refs_file = os.path.join(WORK_DIR, "_all-images.txt")
    with open(refs_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(all_refs) + "\n")

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

    fix_info = {
        e["image"]: {
            "current_tag": e.get("current_tag"),
            "latest_tag": e.get("latest_tag"),
            "status": e.get("status"),
            "fixes": {},          # cve -> earliest tag found to lack it
            "latest_checked": False,
        }
        for e in tag_entries
    }

    needs_update = [e for e in tag_entries if e.get("status") == "NEEDS_UPDATE" and e.get("latest_image")]
    print(f"  {len(tag_entries)} component(s) checked, {len(needs_update)} behind their latest available tag")

    if needs_update:
        # Reuse whatever assertion the current tag's fleet-list line carried --
        # the same simplifying assumption scan.sh's own staleness rescan makes
        # (how RKE2 starts an image doesn't change just because its tag did).
        ref_to_rest = {}
        for pairs in release_lines.values():
            for ref, rest in pairs:
                ref_to_rest.setdefault(ref, rest)

        def current_affected(ref):
            ids = set()
            for (b, r), result in batch_results.items():
                if r == ref:
                    ids |= affected_cve_ids(result)
            return ids

        def repo_part(ref):
            return ref.rsplit(":", 1)[0]

        scan_cache = {}  # image ref at a specific tag -> affected cve id set, or None on failure

        def scan_new_refs(new_refs, round_label):
            """new_refs: {ref: rest}. Scans whatever isn't already cached."""
            to_scan = {r: rest for r, rest in new_refs.items() if r not in scan_cache}
            if not to_scan:
                return
            variants, batches = {}, {}
            for ref, rest in to_scan.items():
                vlist = variants.setdefault(ref, [])
                if rest not in vlist:
                    vlist.append(rest)
                batches.setdefault(vlist.index(rest), {})[ref] = rest
            found = {}
            for b, refs in sorted(batches.items()):
                batch_file = os.path.join(WORK_DIR, f"_{round_label}_batch_{b}.txt")
                with open(batch_file, "w", encoding="utf-8") as fh:
                    for ref, rest in refs.items():
                        fh.write(f"{ref} {rest}\n" if rest else f"{ref}\n")
                scan_file = os.path.join(WORK_DIR, f"_{round_label}_batch_{b}.scan.json")
                print(f"--- {round_label} batch {b}: {len(refs)} image(s) ---")
                run_vexscan(batch_file, scan_file)
                with open(scan_file, encoding="utf-8") as fh:
                    doc = json.load(fh)
                for result in doc.get("results") or []:
                    if result and result.get("target"):
                        found[result["target"]] = affected_cve_ids(result)
            for ref in to_scan:
                scan_cache[ref] = found.get(ref)  # None if it failed to pull/scan

        # Round 0: confirm latest actually fixes something, same as before.
        latest_pairs = {e["latest_image"]: ref_to_rest.get(e["image"], "") for e in needs_update}
        scan_new_refs(latest_pairs, "latest")

        search_state = {}  # ref -> {"candidates": [...], "bounds": {cve: [lo, hi]}}
        for e in needs_update:
            ref = e["image"]
            latest_ids = scan_cache.get(e["latest_image"])
            if latest_ids is None:
                continue  # latest tag could not be pulled/scanned; leave unverified
            fixed_by_latest = current_affected(ref) - latest_ids
            if not fixed_by_latest:
                continue

            all_tags = e.get("all_tags") or []
            try:
                lo_idx = all_tags.index(e["current_tag"])
                hi_idx = all_tags.index(e["latest_tag"])
            except ValueError:
                lo_idx = hi_idx = None

            if lo_idx is None or hi_idx - lo_idx <= 1:
                # Can't place current_tag in the published list, or latest is
                # the very next tag after current -- nothing in between to
                # search, latest itself is already the earliest fix.
                for cve in fixed_by_latest:
                    fix_info[ref]["fixes"][cve] = e["latest_tag"]
                fix_info[ref]["latest_checked"] = True
                continue

            candidates = all_tags[lo_idx + 1: hi_idx + 1]  # candidates[-1] == latest_tag
            search_state[ref] = {
                "candidates": candidates,
                "repo": repo_part(ref),
                "rest": ref_to_rest.get(ref, ""),
                "bounds": {cve: [0, len(candidates) - 1] for cve in fixed_by_latest},
            }
            fix_info[ref]["latest_checked"] = True

        max_rounds = 20  # generous: log2 of even a few thousand tags is ~12
        for round_num in range(max_rounds):
            probes = {}  # image ref at candidate tag -> assertion
            for st in search_state.values():
                for lo, hi in st["bounds"].values():
                    if lo < hi:
                        mid = (lo + hi) // 2
                        probes[f'{st["repo"]}:{st["candidates"][mid]}'] = st["rest"]
            if not probes:
                break
            scan_new_refs(probes, f"fixsearch-r{round_num}")

            still_active = False
            for st in search_state.values():
                for cve, (lo, hi) in st["bounds"].items():
                    if lo >= hi:
                        continue
                    mid = (lo + hi) // 2
                    probe_ref = f'{st["repo"]}:{st["candidates"][mid]}'
                    ids = scan_cache.get(probe_ref)
                    if ids is None or cve in ids:
                        lo = mid + 1  # still present, or couldn't verify: keep searching upward
                    else:
                        hi = mid
                    st["bounds"][cve] = [lo, hi]
                    if lo < hi:
                        still_active = True
            if not still_active:
                break

        for ref, st in search_state.items():
            for cve, (lo, _hi) in st["bounds"].items():
                fix_info[ref]["fixes"][cve] = st["candidates"][lo]

    fix_info_path = os.path.join(WORK_DIR, "fix_info.json")
    with open(fix_info_path, "w", encoding="utf-8") as fh:
        json.dump(fix_info, fh)
    print(f"  wrote {fix_info_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
