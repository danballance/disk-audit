# disk-audit

A read-only Python CLI for repeatable disk-space investigations on **macOS and Linux**.
It reports partition allocation, filesystem capacity, large directories/files, and
cleanup candidates. It never deletes, moves, truncates, mounts, changes permissions,
invokes sudo, or executes cleanup commands. File scanning reads metadata only, not
file contents. It has no runtime dependencies and supports Python 3.9+.

## Run with uvx

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if necessary.
From a checkout:

```sh
uvx --from . disk-audit
```

From anywhere on this Mac:

```sh
uvx --from /Users/danballance/Code/python/disk-audit disk-audit
```

On Linux, copy/clone this project and substitute its local path. The distribution
name is `disk-space-audit`; the executable is `disk-audit`. It has **not** been
published to PyPI. A bare `uvx disk-audit` would look up another package rather than
necessarily run this code. After publishing your repository, a Git source can be
used with `uvx --from git+https://YOUR-REPOSITORY-URL disk-audit`.

uv creates its own package/build caches and isolated environments. The auditor
itself writes only to stdout/stderr. Packaging is therefore not a zero-write
operation, even though the scan is read-only. For a direct standard-library run
without installing/building the package:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m disk_audit
```

## Repeatable reports

```sh
# Default scope, 2-minute scanning budget, 15 seconds per scan unit
uvx --from . disk-audit

# Focus on particular directories; repeat --path to add roots
uvx --from . disk-audit --path "$HOME" --path /opt --budget 300 --timeout 30

# More detail; exclude an exact subtree
uvx --from . disk-audit --min-size-mb 20 --top 40 --exclude "$HOME/Code"

# Machine-readable report: shell redirection intentionally creates this output file
uvx --from . disk-audit --format json > disk-report.json

# Scripted checks return exit code 2 for incomplete coverage
uvx --from . disk-audit --strict --format json > disk-report.json

# File scans only, with no platform inventory commands
uvx --from . disk-audit --path "$HOME/.nx" --no-system
```

Progress goes to stderr, so JSON on stdout remains parseable. Use `--quiet` to
suppress progress. `--budget` covers directory discovery and file scans; OS
inventory happens beforehand (individual inventory commands have five-second
timeouts). Ctrl-C during a scan stops workers and emits a partial report with
exit code 130. Exit 0 normally means a report was produced, not that every path
was accessible. Use `--strict` to detect incomplete scans or inventory failures.

## Scope and interpretation

- Default macOS roots: your home, `/Library`, `/Applications`, `/opt`,
  `/private/var`, and `/Users/Shared`.
- Default Linux roots: your home, `/var`, `/usr`, `/opt`, `/nix`, and `/srv`.
  Add other users, `/home`, mounted data volumes, or other paths explicitly.
- Roots are split into separately timed scan units. macOS Library namespaces
  are split further so one protected app directory cannot stall other scans.
- Symlinks, sockets, devices, FIFOs and nested mount points are skipped. Supply a
  mounted filesystem as its own explicit root if you want to scan it. Explicit
  nested roots are measured separately and excluded from their ancestor's scan
  to avoid counting their files twice. Linux bind mounts are read from mountinfo.
  Symlink roots are skipped too; supply the real path.
- The JSON `scans` array records each unit's status, including permission errors,
  timeouts and work not started before the budget expired. Progress snapshots
  retain already measured files and completed subdirectories when a unit times out.
  A `discovery_only` unit counts its directory inode and loose files, not its
  separately scheduled child directories. Ranked directory summaries roll these
  units up and mark the parent partial if a child was incomplete. Missing paths
  remain explicit failures. Optional default roots absent on a machine are omitted.
- Sizes use `st_blocks * 512`, so sparse files are measured by allocated storage.
  Apparent file sizes are also available. Hard links are deduplicated within a
  scan unit, but may be counted in multiple independent units. Directory rows
  include descendants; **do not sum parent and child rows or candidate rows**.
- APFS clones, compressed files, Btrfs reflinks, snapshots, filesystem metadata,
  protected paths and skipped mounts prevent an exact reconciliation with `df`.
  Candidate sizes are occupied space, not guaranteed reclaimable space.
- Filesystem capacity rows may describe the same filesystem or shared APFS
  container. Linux disk/partition/LVM rows also overlap. Do not sum these rows.
- macOS inventory uses `diskutil` plist output, including Data snapshots. Linux
  uses `lsblk` and `findmnt`; missing utilities are reported gracefully. Linux
  snapshots and Nix reachability are not analyzed.
- Linux/Asahi partition allocation is visible from macOS, but its internal usage
  is not inferred. Small APFS/EFI partitions may be required for Asahi booting.
  An almost-empty partition is **not** classified as safe to remove.
- macOS privacy permissions can hide Mail, Photos, Trash and other app data.
  Unlocking the Mac may allow access prompts to appear. Any access/permission
  changes are up to you; the auditor never makes them.

Hints recognize old NoMachine session logs, models, VM bundles, Android emulators,
caches, downloads, music libraries and some build/dependency folders. They are
path-based suggestions. Source code, VM disks, Docker volumes, sound libraries and
download folders may contain unique data. Check the owning application before
acting. The tool neither checks open file handles nor guarantees any file is safe
to delete. NoMachine `F-C-`/`F-S-`/`T-C-` session logs are distinguished from JavaScript
Nx caches; see [NoMachine's session-directory documentation](https://kb.nomachine.com/AR12K00765).

## Develop and build with uv

```sh
uv sync
uv run python -m unittest discover -s tests -v
uv build
uvx --from dist/disk_space_audit-0.1.0-py3-none-any.whl disk-audit --help
```

The tests cover allocated vs apparent sizes, hard links, symlinks, special files,
mount boundaries, permission errors, exclusions, subprocess deadlines, partial
reports, OS inventory fixtures, JSON output, and read-only scan behavior.
The GitHub Actions workflow runs the same suite on macOS and Linux.
