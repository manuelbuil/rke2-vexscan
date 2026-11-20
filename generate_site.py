#!/usr/bin/env python3
"""generate_site.py -- render a CVE-by-component lookup site for a set of
scanned RKE2 releases.

Reads every reports/releases/<slug>/{release.txt,scan.json} written by
scan-matrix.sh + build-matrix-scan.py and renders:

  site/index.html        -- one card per release, grouped by minor version
  site/<slug>/index.html -- that release's affected CVEs, one row per
                             (CVE, component) pair, grouped by component

Only *affected* findings are shown (status linked/reachable, not exculpated
by a VEX statement) -- the same classification vexscan's own
contrib/vexscan-dashboard.py uses (its bucket_of()), so this site's numbers
agree with the rest of the project's tooling about what counts as "affected".

Python 3.8+, standard library only.

    python3 generate_site.py reports/releases site
"""

import html
import json
import os
import re
import sys

EXCULPATORY = ("not_affected", "fixed")
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2, "MEDIUM": 3, "LOW": 4, "NONE": 5}
RELEASE_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)\+rke2r(\d+)$")

CSS = """
:root {
  --bg: #0b0e14;
  --panel: #131722;
  --border: #232838;
  --text: #e6e8ef;
  --muted: #8b92a8;
  --link: #6ea8fe;
  --crit: #ff5c72;
  --high: #ff9f43;
  --unknown: #8b92a8;
  --med: #ffd166;
  --low: #5ec3ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
header {
  padding: 2rem 2rem 1rem;
  border-bottom: 1px solid var(--border);
}
header h1 { margin: 0 0 .25rem; font-size: 1.5rem; }
header p { margin: 0; color: var(--muted); }
main { padding: 2rem; max-width: 1100px; margin: 0 auto; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
.minor-group { margin-bottom: 2.5rem; }
.minor-group h2 { font-size: 1.1rem; color: var(--muted); font-weight: 600; margin-bottom: .75rem; }
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 1rem;
}
.card {
  display: block;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1rem 1.1rem;
}
.card:hover { border-color: var(--link); text-decoration: none; }
.card .tag { font-weight: 600; font-size: 1.05rem; color: var(--text); }
.card .total { margin-top: .5rem; font-size: 1.6rem; font-weight: 700; }
.card .total.zero { color: var(--muted); }
.card .breakdown { margin-top: .4rem; font-size: .8rem; color: var(--muted); }
.badge {
  display: inline-block;
  padding: .1rem .5rem;
  border-radius: 999px;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .02em;
}
.badge-CRITICAL { background: color-mix(in srgb, var(--crit) 25%, transparent); color: var(--crit); }
.badge-HIGH { background: color-mix(in srgb, var(--high) 25%, transparent); color: var(--high); }
.badge-UNKNOWN { background: color-mix(in srgb, var(--unknown) 25%, transparent); color: var(--unknown); }
.badge-MEDIUM { background: color-mix(in srgb, var(--med) 25%, transparent); color: var(--med); }
.badge-LOW { background: color-mix(in srgb, var(--low) 25%, transparent); color: var(--low); }
.summary { color: var(--muted); margin-bottom: 1.25rem; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; }
tr.component-first td { border-top: 1px solid var(--border); }
.component { font-weight: 600; }
.muted { color: var(--muted); }
.fix-yes { color: #4fd07a; font-weight: 600; }
.fix-no { color: var(--crit); }
.back { display: inline-block; margin-bottom: 1.25rem; color: var(--muted); }
"""


def esc(s):
    return html.escape(str(s), quote=True)


def is_affected(finding):
    if finding.get("status") not in ("linked", "reachable"):
        return False
    vex = finding.get("vex") or {}
    return vex.get("status") not in EXCULPATORY


def severity_of(finding):
    sev = (finding.get("severity") or "").strip()
    return sev if sev else "UNKNOWN"


def component_of(target):
    last = target.rsplit("/", 1)[-1]
    return last.rsplit(":", 1)[0]


def tag_of(target):
    last = target.rsplit("/", 1)[-1]
    return last.rsplit(":", 1)[-1] if ":" in last else ""


def load_fix_info(reports_dir):
    path = os.path.join(reports_dir, "fix_info.json")
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fix_cell(target, cve, fix_info):
    info = fix_info.get(target)
    if info is None:
        return '<span class="muted">unknown</span>'
    status = info.get("status")
    latest_tag = info.get("latest_tag")
    if status == "UP_TO_DATE":
        return '<span class="muted">already on latest tag</span>'
    if status != "NEEDS_UPDATE" or not latest_tag:
        return '<span class="muted">no newer build found</span>'
    if not info.get("latest_checked"):
        return f'<span class="muted">{esc(latest_tag)} (not verified)</span>'
    fix_tag = (info.get("fixes") or {}).get(cve)
    if fix_tag:
        return f'<span class="fix-yes">{esc(fix_tag)}</span>'
    return f'<span class="fix-no">still present at {esc(latest_tag)}</span>'


def advisory_url(ident):
    up = (ident or "").upper()
    if up.startswith("CVE-"):
        return "https://nvd.nist.gov/vuln/detail/" + ident
    if up.startswith("GHSA-"):
        return "https://github.com/advisories/" + ident
    if up.startswith("GO-"):
        return "https://pkg.go.dev/vuln/" + ident
    if not ident:
        return ""
    return "https://osv.dev/vulnerability/" + ident


def badge(sev):
    return '<span class="badge badge-%s">%s</span>' % (esc(sev), esc(sev))


def load_releases(reports_dir):
    releases = []
    for slug in sorted(os.listdir(reports_dir)):
        dir_path = os.path.join(reports_dir, slug)
        release_txt = os.path.join(dir_path, "release.txt")
        scan_json = os.path.join(dir_path, "scan.json")
        if not (os.path.isfile(release_txt) and os.path.isfile(scan_json)):
            continue
        with open(release_txt, encoding="utf-8") as fh:
            tag = fh.read().strip()
        m = RELEASE_RE.match(tag)
        if not m:
            print(f"warning: {tag!r} ({dir_path}) doesn't look like a stable RKE2 release tag; skipping", file=sys.stderr)
            continue
        major, minor, patch, rn = (int(x) for x in m.groups())
        with open(scan_json, encoding="utf-8") as fh:
            doc = json.load(fh)

        rows = []
        for result in doc.get("results") or []:
            target = result.get("target", "")
            component = component_of(target)
            for finding in result.get("findings") or []:
                if not is_affected(finding):
                    continue
                rows.append({
                    "severity": severity_of(finding),
                    "cve": finding.get("id") or finding.get("cve") or "",
                    "component": component,
                    "target": target,
                })
        rows.sort(key=lambda r: (r["component"], SEVERITY_RANK.get(r["severity"], 6), r["cve"]))

        counts = {}
        for r in rows:
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        worst = min(counts, key=lambda s: SEVERITY_RANK.get(s, 6)) if counts else None

        releases.append({
            "slug": slug,
            "tag": tag,
            "major": major, "minor": minor, "patch": patch, "rn": rn,
            "rows": rows,
            "counts": counts,
            "worst": worst,
            "failures": doc.get("failures") or [],
        })
    return releases


def render_release_page(rel, out_dir, fix_info):
    total = len(rel["rows"])
    summary_bits = ", ".join(
        f"{rel['counts'][s]} {s}" for s in sorted(rel["counts"], key=lambda s: SEVERITY_RANK.get(s, 6))
    ) or "none"

    body_rows = []
    last_component = None
    for row in rel["rows"]:
        first = row["component"] != last_component
        last_component = row["component"]
        cls = ' class="component-first"' if first else ""
        component_cell = f'<span class="component">{esc(row["component"])}</span>' if first else ""
        tag_cell = esc(tag_of(row["target"])) if first else ""
        url = advisory_url(row["cve"])
        cve_link = f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer">{esc(row["cve"])}</a>' if url else esc(row["cve"])
        fix = fix_cell(row["target"], row["cve"], fix_info)
        body_rows.append(
            f'<tr{cls}><td>{badge(row["severity"])}</td><td>{cve_link}</td>'
            f'<td>{component_cell}</td><td>{tag_cell}</td><td>{fix}</td></tr>'
        )

    failure_note = ""
    if rel["failures"]:
        names = ", ".join(esc(f.get("target", "?")) for f in rel["failures"])
        failure_note = (
            f'<p class="summary">⚠ {len(rel["failures"])} image(s) could not be scanned '
            f'and are not reflected below: {names}</p>'
        )

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{esc(rel['tag'])} -- RKE2 CVE lookup</title>
<style>{CSS}</style></head>
<body>
<header>
<h1>{esc(rel['tag'])}</h1>
<p>{total} CVE/component finding(s) affecting this release &mdash; {summary_bits}</p>
</header>
<main>
<a class="back" href="../index.html">&larr; All releases</a>
{failure_note}
<table>
<thead><tr><th>Severity</th><th>CVE</th><th>Component</th><th>Current tag</th><th>Fixes in</th></tr></thead>
<tbody>
{''.join(body_rows) if body_rows else '<tr><td colspan="5" class="muted">No affected CVEs found.</td></tr>'}
</tbody>
</table>
</main>
</body></html>
"""
    rel_dir = os.path.join(out_dir, rel["slug"])
    os.makedirs(rel_dir, exist_ok=True)
    with open(os.path.join(rel_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(doc)


def render_card(rel):
    total = len(rel["rows"])
    total_cls = " zero" if total == 0 else ""
    worst_badge = badge(rel["worst"]) if rel["worst"] else ""
    breakdown = ", ".join(
        f"{rel['counts'][s]} {s.lower()}" for s in sorted(rel["counts"], key=lambda s: SEVERITY_RANK.get(s, 6))
    ) or "no affected CVEs"
    return f"""<a class="card" href="{esc(rel['slug'])}/index.html">
<div class="tag">{esc(rel['tag'])}</div>
<div class="total{total_cls}">{total} {worst_badge}</div>
<div class="breakdown">{esc(breakdown)}</div>
</a>"""


def render_index(releases, out_dir):
    groups = {}
    for rel in releases:
        groups.setdefault((rel["major"], rel["minor"]), []).append(rel)

    sections = []
    for (major, minor), group in sorted(groups.items()):
        group.sort(key=lambda r: (r["patch"], r["rn"]))
        cards = "\n".join(render_card(r) for r in group)
        sections.append(f"""<div class="minor-group">
<h2>{major}.{minor}</h2>
<div class="card-grid">{cards}</div>
</div>""")

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>RKE2 CVE lookup</title>
<style>{CSS}</style></head>
<body>
<header>
<h1>RKE2 CVE lookup</h1>
<p>Find your RKE2 release below to see which CVEs affect it and which component each one is in.</p>
</header>
<main>
{''.join(sections)}
</main>
</body></html>
"""
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    if len(sys.argv) != 3:
        print("Usage: generate_site.py <reports/releases dir> <output site dir>", file=sys.stderr)
        return 1
    reports_dir, out_dir = sys.argv[1], sys.argv[2]

    releases = load_releases(reports_dir)
    if not releases:
        print("No scanned releases found.", file=sys.stderr)
        return 1
    fix_info = load_fix_info(reports_dir)
    if not fix_info:
        print("warning: no fix_info.json found; 'Fixes in' column will show 'unknown' everywhere", file=sys.stderr)

    for rel in releases:
        render_release_page(rel, out_dir, fix_info)
    render_index(releases, out_dir)

    print(f"Rendered {len(releases)} release page(s) to {out_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
