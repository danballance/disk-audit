from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import sys
import time

from . import __version__
from .scan import advice, scan
from .system import default_roots, inventory, normalize_paths


def size(value):
    if value is None:
        return "unknown"
    return f"{int(value) / 1_000_000_000:,.2f} GB"


def safe(value):
    # Avoid terminal control characters in filenames, mount labels, or error text.
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


def ranked(results, key, limit):
    items = {}
    for result in results:
        for item in result.get(key, []):
            previous = items.get(item["path"])
            if previous is None or item["allocated_bytes"] > previous["allocated_bytes"]:
                items[item["path"]] = item
    return sorted(items.values(), key=lambda i: i["allocated_bytes"], reverse=True)[:limit]


def rollups(results, minimum):
    """Combine discovery units with their separately measured children."""
    nodes = {s["path"]: {"path": s["path"], "allocated_bytes": s["allocated_bytes"],
                          "complete": s["status"] == "complete",
                          "discovery": s.get("discovery_only", False)} for s in results}
    for path in sorted(nodes, key=len, reverse=True):
        parent = nodes.get(os.path.dirname(path))
        if parent and parent["discovery"]:
            parent["allocated_bytes"] += nodes[path]["allocated_bytes"]
            parent["complete"] &= nodes[path]["complete"]
    directories = [{k: v for k, v in node.items() if k != "discovery"}
                   for node in nodes.values() if node["discovery"] and node["allocated_bytes"] >= minimum]
    candidates = []
    for item in directories:
        hint = advice(item["path"], True)
        if hint:
            candidates.append(dict(item, category=hint[0], advice=hint[1]))
    return {"large_directories": directories, "candidates": candidates}


def render(report, top):
    lines = [f"Disk audit {__version__} — {report['created_at']}",
             "Read-only metadata scan. Sizes use decimal GB; no deletion is performed.", "",
             "Disk allocation (nested devices/containers overlap; do not add these rows):"]
    system = report["system"]
    for row in system["partitions"]:
        line = f"  {size(row.get('size_bytes')):>13}  {safe(row['device'])}  {safe(row['kind'])}  {safe(row['name'])}"
        if row.get("free_bytes") is not None:
            line += f"; container free {size(row['free_bytes'])}"
        if row.get("volumes"):
            line += "; " + safe(", ".join(row["volumes"]))
        lines.append(line)
    if not system["partitions"]:
        lines.append("  Partition inventory skipped or unavailable; see coverage notes below.")
    lines += ["", "Filesystem capacity (APFS volumes can share free space; do not sum):"]
    for row in system["filesystems"]:
        if "error" in row:
            lines.append(f"  {safe(row['path'])}: {safe(row['error'])}")
        else:
            lines.append(f"  {safe(row['path'])}: {size(row['total_bytes'])} total / "
                         f"{size(row['used_bytes'])} used / {size(row['free_bytes'])} available")
    for title, key in (("Largest measured directories", "large_directories"),
                       ("Largest measured files", "large_files")):
        lines += ["", title + " (allocated storage; parent and child rows overlap):"]
        for item in report[key]:
            partial = " [partial]" if not item["complete"] else ""
            line = f"  {size(item['allocated_bytes']):>13}  {safe(item['path'])}{partial}"
            if key == "large_files":
                line += f"; modified {datetime.datetime.fromtimestamp(item['modified']).date()}"
                if item["apparent_bytes"] > item["allocated_bytes"] * 1.2:
                    line += f"; apparent {size(item['apparent_bytes'])}"
            lines.append(line)
    lines += ["", "Cleanup candidates (review suggestions, not guaranteed recoverable space):"]
    for item in report["candidates"]:
        partial = " [partial]" if not item["complete"] else ""
        lines += [f"  {size(item['allocated_bytes']):>13}  {safe(item['path'])}{partial}",
                  f"    {item['category']}: {item['advice']}"]
    if not report["candidates"]:
        lines.append("  No recognized candidates above the chosen threshold were measured.")
    scans = report["scans"]
    incomplete = [s for s in scans if s["status"] != "complete"]
    lines += ["", f"Coverage: {len(scans) - len(incomplete)}/{len(scans)} scan units completed; "
              f"elapsed {report['elapsed_seconds']:.1f}s."]
    if report["exclusions"]:
        lines.append("  Explicit exclusions: " + safe(", ".join(report["exclusions"])))
    for item in incomplete[:top]:
        lines.append(f"  {item['status']}: {safe(item['path'])}")
        for error in item.get("errors", [])[:2]:
            lines.append(f"    {safe(error['reason'])}")
    if len(incomplete) > top:
        lines.append(f"  {len(incomplete) - top} more incomplete units; use --format json for all paths.")
    for name, result in system["commands"].items():
        if "error" in result:
            lines.append(f"  {name} unavailable: {safe(result['error'])}")
    snapshots = system["commands"].get("snapshots", {}).get("data")
    if snapshots is not None:
        count = len(snapshots.get("Snapshots", []))
        lines.append(f"  macOS Data snapshots reported: {count}; snapshot sizes are not estimated.")
    lines += ["  Symlinks, nested mounts, and special files are skipped. Other users and some system paths",
              "  are outside the default scope. Missing/inaccessible data is unknown, not zero.",
              "  Hard links are deduplicated within each scan unit only. APFS clones, compression,",
              "  snapshots and filesystem metadata prevent exact reconciliation with disk capacity.",
              "  Partition allocation is not filesystem usage. Never delete boot/recovery or Linux",
              "  partitions based on this report. No filesystem is mounted and no sudo is invoked."]
    return "\n".join(lines) + "\n"


def positive_float(value):
    number = float(value)
    if not 0 < number < float("inf"):
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only disk analysis for macOS and Linux. No cleanup commands.")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--path", action="append", help="Scan this path instead of defaults; repeatable. Symlinks are not followed.")
    parser.add_argument("--exclude", action="append", default=[], help="Skip this exact path and its subtree; repeatable.")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-size-mb", type=positive_float, default=100, help="Reporting threshold in decimal MB (default: 100).")
    parser.add_argument("--top", type=positive_int, default=20, help="Rows per ranked section (default: 20).")
    parser.add_argument("--workers", type=positive_int, default=4, help="Concurrent scan processes (default: 4).")
    parser.add_argument("--timeout", type=positive_float, default=15, help="Seconds per scan unit (default: 15).")
    parser.add_argument("--budget", type=positive_float, default=120, help="Overall file-scan time limit in seconds (default: 120).")
    parser.add_argument("--no-system", action="store_true", help="Skip disk inventory commands and filesystem-capacity queries.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress on stderr.")
    parser.add_argument("--strict", action="store_true", help="Exit 2 if any scan or inventory command was incomplete.")
    args = parser.parse_args(argv)
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("supported platforms are macOS and Linux")
    roots = normalize_paths(args.path or default_roots(), collapse=False)
    exclusions = normalize_paths(args.exclude)
    # Prevent scanning descendants of an excluded ancestor, including explicit roots.
    roots = [r for r in roots if not any(os.path.commonpath([r, x]) == x for x in exclusions)]
    if not roots:
        parser.error("no roots remain after exclusions")
    started = time.monotonic()
    last = [0.0]
    def progress(done, active, queued):
        now = time.monotonic()
        if not args.quiet and now - last[0] > 10:
            print(f"Scanned {done} units; {active} running, {queued} queued.", file=sys.stderr, flush=True)
            last[0] = now
    if not args.quiet:
        print("Collecting read-only storage metadata…", file=sys.stderr, flush=True)
    system = inventory(roots) if not args.no_system else {
        "platform": platform.system(), "filesystems": [], "partitions": [], "commands": {}}
    results, interrupted = scan(roots, int(args.min_size_mb * 1_000_000), args.top,
                                args.workers, args.timeout, args.budget, exclusions, progress)
    summaries = rollups(results, int(args.min_size_mb * 1_000_000))
    report = {"schema_version": 1, "version": __version__,
              "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "roots": roots, "exclusions": exclusions, "system": system, "scans": results,
              "large_files": ranked(results, "large_files", args.top),
              "large_directories": ranked(results + [summaries], "large_directories", args.top),
              "candidates": ranked(results + [summaries], "candidates", args.top)}
    if args.format == "json":
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render(report, args.top), end="")
    if interrupted:
        return 130
    incomplete = any(s["status"] != "complete" for s in results)
    incomplete |= any("error" in x for x in system["commands"].values())
    incomplete |= any("error" in x for x in system["filesystems"])
    return 2 if args.strict and incomplete else 0
