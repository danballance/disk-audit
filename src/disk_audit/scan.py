"""Metadata-only scans in disposable processes, including directory discovery."""
from __future__ import annotations

import heapq
import multiprocessing as mp
import os
import stat
import time
from collections import deque
from pathlib import Path


def linux_mountpoints():
    """Include same-device Linux bind mounts that os.path.ismount cannot detect."""
    mounts = set()
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            for line in stream:
                fields = line.split()
                if len(fields) > 4:
                    value = fields[4]
                    for escaped, literal in (("\\040", " "), ("\\011", "\t"),
                                             ("\\012", "\n"), ("\\134", "\\")):
                        value = value.replace(escaped, literal)
                    mounts.add(value)
    except OSError:
        pass
    return mounts


def advice(path: str, is_dir: bool) -> tuple[str, str] | None:
    """Conservative path-based hints, never an assertion that deletion is safe."""
    p = Path(path)
    parts = p.parts
    if (not is_dir and p.name == "session" and ".nx" in parts
            and p.parent.name.startswith(("F-C-", "F-S-", "T-C-"))):
        return "old session log", "NoMachine failed/terminated-session log; review age and active sessions."
    if is_dir and p.name == "models" and any(x in parts for x in (".ollama", ".lmstudio")):
        return "downloaded models", "Remove unused models with the owning application; downloads may be shared."
    if is_dir and (p.suffix in (".pvm", ".utm") or p.name == "avd"):
        return "virtual machine", "Review unused VMs/devices; these may contain unique files and saved state."
    if is_dir and p.name == "com.docker.docker":
        return "container data", "Inspect Docker's storage UI or system df; volumes may contain unique data."
    if is_dir and (p.name in (".Trash", "Trash", ".local-trash") or p.name.startswith(".Trash-")):
        return "trash", "Review contents before emptying; this is the last recoverable copy of deleted files."
    if is_dir and p.name in ("Downloads", "downloads"):
        return "downloads", "Review old installers and archives individually; the folder can contain original files."
    if is_dir and (p.name in (".npm", ".cache", "Caches") or p.parent.name in ("Caches", ".cache")):
        return "cache", "Prefer the application's cache cleanup; data may be downloaded or rebuilt afterward."
    if is_dir and (p.name in ("Arturia", "installed-packages")
                   or str(p) in ("/Library/Application Support/Logic", "/Library/Audio/Plug-Ins")):
        return "music assets", "Review unused products/packs or relocate through the product manager."
    if is_dir and p.name in ("node_modules", ".venv", "DerivedData"):
        return "build/dependency data", "Rebuildable if dependencies and source are preserved; review project needs."
    if is_dir and str(p) == "/nix/store":
        return "Nix store", "Use Nix's own storage tools to inspect roots/generations; never delete store files manually."
    return None


class Scanner:
    def __init__(self, send, minimum=100_000_000, top=20, exclusions=()):
        self.send = send
        self.minimum = minimum
        self.top = top
        self.exclusions = set(exclusions)
        self.files = []
        self.directories = []
        self.candidates = []
        self.errors = []
        self.error_count = 0
        self.allocated = self.apparent = self.file_count = 0
        self.symlinks = self.mounts = self.excluded = 0
        self.seen = set()
        self.last_update = 0.0
        self.root = ""
        self.mountpoints = linux_mountpoints()

    def error(self, path, reason):
        self.error_count += 1
        if len(self.errors) < 10:
            self.errors.append({"path": str(path), "reason": str(reason)})

    def keep(self, heap, size, item):
        # Paths are unique within each heap and break ties without comparing dicts.
        heapq.heappush(heap, (size, item["path"], item))
        if len(heap) > self.top:
            heapq.heappop(heap)

    def result(self, status):
        return {
            "path": self.root, "status": status,
            "allocated_bytes": self.allocated, "apparent_bytes": self.apparent,
            "files_seen": self.file_count, "errors": self.errors,
            "error_count": self.error_count, "symlinks_skipped": self.symlinks,
            "mounts_skipped": self.mounts, "excluded": self.excluded,
            "large_files": [x[2] for x in sorted(self.files, reverse=True)],
            "large_directories": [x[2] for x in sorted(self.directories, reverse=True)],
            "candidates": [x[2] for x in sorted(self.candidates, reverse=True)],
        }

    def tick(self, force=False):
        now = time.monotonic()
        if force or now - self.last_update >= 0.5:
            self.send({"kind": "progress", "result": self.result("scanning")})
            self.last_update = now

    def walk(self, path, device, discover=False):
        self.tick()
        if path in self.exclusions:
            self.excluded += 1
            return 0
        try:
            info = os.lstat(path)
        except OSError as exc:
            self.error(path, exc)
            return 0
        if stat.S_ISLNK(info.st_mode):
            self.symlinks += 1
            return 0
        if info.st_dev != device or (path != self.root and (path in self.mountpoints or os.path.ismount(path))):
            self.mounts += 1
            return 0
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            return 0  # No sockets, devices, FIFOs, or their contents.
        identity = (info.st_dev, info.st_ino)
        if identity in self.seen:
            return 0
        # Only multiply-linked files need inode tracking; avoid O(all files) memory.
        if info.st_nlink > 1 and stat.S_ISREG(info.st_mode):
            self.seen.add(identity)
        size = info.st_blocks * 512
        self.allocated += size
        is_dir = stat.S_ISDIR(info.st_mode)
        start_errors = self.error_count
        if is_dir:
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        self.tick()
                        child = entry.path
                        if child in self.exclusions:
                            self.excluded += 1
                            continue
                        # Discovery runs inside a worker too: scandir/stat can block.
                        if discover and entry.is_dir(follow_symlinks=False):
                            child_stat = entry.stat(follow_symlinks=False)
                            if child_stat.st_dev == device and child not in self.mountpoints and not os.path.ismount(child):
                                self.send({"kind": "child", "path": child})
                            else:
                                self.mounts += 1
                        else:
                            size += self.walk(child, device)
            except OSError as exc:
                self.error(path, exc)
        else:
            self.file_count += 1
            self.apparent += info.st_size
        item = {"path": path, "allocated_bytes": size,
                "complete": self.error_count == start_errors,
                "modified": info.st_mtime}
        if not is_dir:
            item["apparent_bytes"] = info.st_size
        if size >= self.minimum and not (is_dir and discover):
            self.keep(self.directories if is_dir else self.files, size, item)
            hint = advice(path, is_dir)
            if hint:
                self.keep(self.candidates, size, dict(item, category=hint[0], advice=hint[1]))
        return size

    def run(self, path, discover):
        self.root = path
        self.tick(force=True)
        try:
            info = os.lstat(path)
            discover = discover and stat.S_ISDIR(info.st_mode)
            self.walk(path, info.st_dev, discover)
        except (OSError, RecursionError) as exc:
            self.error(path, exc)
        result = self.result("partial" if self.error_count else "complete")
        result["discovery_only"] = discover
        self.send({"kind": "done", "result": result})


def worker(connection, path, discover, minimum, top, exclusions):
    try:
        Scanner(connection.send, minimum, top, exclusions).run(path, discover)
    finally:
        connection.close()


def should_expand(path):
    """Split large macOS app-data namespaces to isolate privacy stalls."""
    p = Path(path)
    return p.name == "Library" or (p.parent.name == "Library" and p.name in (
        "Caches", "Application Support", "Containers", "Group Containers"))


def scan(roots, minimum, top, workers, timeout, budget, exclusions=(), progress=None):
    context = mp.get_context("spawn")
    queue = deque((p, True) for p in roots)
    active = []
    results = []
    started = time.monotonic()
    discovered = set(roots)
    interrupted = False

    def stop(job, status):
        process = job["process"]
        if process.is_alive():
            process.terminate()
        process.join(0.1)
        if process.is_alive():
            process.kill()
            process.join(0.1)
        job["pipe"].close()
        result = job["last"] or {"path": job["path"], "allocated_bytes": 0,
                                  "large_files": [], "large_directories": [], "candidates": []}
        result["status"] = status
        result.setdefault("discovery_only", job["discover"])
        results.append(result)
        active.remove(job)

    try:
        while queue or active:
            if time.monotonic() - started >= budget:
                break
            while queue and len(active) < workers:
                path, discover = queue.popleft()
                receive, send = context.Pipe(duplex=False)
                # Explicit nested roots are scanned separately, never twice.
                omit = tuple(exclusions) + tuple(r for r in roots if r != path)
                process = context.Process(target=worker, args=(send, path, discover, minimum, top, omit))
                process.start()
                send.close()
                active.append({"process": process, "pipe": receive, "path": path,
                               "discover": discover, "start": time.monotonic(), "last": None})
            for job in active[:]:
                # Bound draining so an enormous directory cannot starve deadlines.
                finished = False
                for _ in range(100):
                    if not job["pipe"].poll():
                        break
                    try:
                        message = job["pipe"].recv()
                    except EOFError:
                        break
                    if message["kind"] == "child":
                        path = message["path"]
                        if path not in discovered:
                            discovered.add(path)
                            queue.append((path, should_expand(path)))
                    else:
                        job["last"] = message["result"]
                        if message["kind"] == "done":
                            stop(job, message["result"]["status"])
                            finished = True
                            break
                if not finished:
                    if time.monotonic() - job["start"] >= timeout:
                        stop(job, "timeout")
                    elif not job["process"].is_alive():
                        stop(job, "failed")
            if progress:
                progress(len(results), len(active), len(queue))
            time.sleep(0.02)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        for job in active[:]:
            stop(job, "interrupted" if interrupted else "budget_exceeded")
    for path, discover in queue:
        results.append({"path": path, "status": "not_scanned", "discovery_only": discover,
                        "allocated_bytes": 0, "large_files": [], "large_directories": [], "candidates": []})
    return results, interrupted
