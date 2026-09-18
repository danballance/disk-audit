"""Read-only OS inventory. A missing command or permission is a report field."""
from __future__ import annotations

import json
import os
import platform
import plistlib
import shutil
import subprocess
from pathlib import Path


def command(argv, parser=None, timeout=5):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        if result.returncode:
            return {"command": argv, "error": result.stderr.decode(errors="replace").strip()
                    or result.stdout.decode(errors="replace").strip() or "command failed"}
        value = parser(result.stdout) if parser else result.stdout.decode(errors="replace").strip()
        return {"command": argv, "data": value}
    except (OSError, subprocess.TimeoutExpired, ValueError, plistlib.InvalidFileException) as exc:
        return {"command": argv, "error": str(exc)}


def mac_rows(disks, apfs):
    rows = []
    containers = {x.get("ContainerReference"): x for x in apfs.get("Containers", [])}
    stores = {store.get("DeviceIdentifier"): container
              for container in containers.values() for store in container.get("PhysicalStores", [])}
    for disk in disks.get("AllDisksAndPartitions", []):
        # A synthesized APFS container duplicates its physical partition capacity.
        if disk.get("Content") not in ("GUID_partition_scheme", "FDisk_partition_scheme"):
            continue
        rows.append({"device": disk.get("DeviceIdentifier"), "kind": "disk",
                     "size_bytes": disk.get("Size"), "name": "Physical disk"})
        for part in disk.get("Partitions", []):
            container = stores.get(part.get("DeviceIdentifier"),
                                   containers.get(part.get("APFSContainerReference"), {}))
            rows.append({"device": part.get("DeviceIdentifier"), "kind": "partition",
                         "size_bytes": part.get("Size"),
                         "name": part.get("VolumeName") or part.get("Content", ""),
                         "container": container.get("ContainerReference"),
                         "free_bytes": container.get("CapacityFree"),
                         "volumes": [v.get("Name", "") for v in container.get("Volumes", [])]})
    return rows


def linux_rows(data):
    rows = []
    def visit(device, level=0):
        rows.append({"device": device.get("path") or device.get("name"),
                     "kind": device.get("type", ""), "size_bytes": device.get("size"),
                     "name": device.get("label") or device.get("fstype") or "",
                     "mounts": device.get("mountpoints") or [device.get("mountpoint")], "level": level})
        for child in device.get("children", []):
            visit(child, level + 1)
    for device in data.get("blockdevices", []):
        visit(device)
    return rows


def inventory(roots):
    system = platform.system()
    result = {"platform": system, "filesystems": [], "partitions": [], "commands": {}}
    # These rows share storage on APFS; never sum them.
    for root in dict.fromkeys(["/"] + roots):
        try:
            usage = shutil.disk_usage(root)
            result["filesystems"].append({"path": root, "total_bytes": usage.total,
                                          "used_bytes": usage.used, "free_bytes": usage.free})
        except OSError as exc:
            result["filesystems"].append({"path": root, "error": str(exc)})
    if system == "Darwin":
        disks = command(["diskutil", "list", "-plist"], plistlib.loads)
        apfs = command(["diskutil", "apfs", "list", "-plist"], plistlib.loads)
        result["commands"].update(disks=disks, apfs=apfs)
        result["partitions"] = mac_rows(disks.get("data", {}), apfs.get("data", {}))
        result["commands"]["snapshots"] = command(
            ["diskutil", "apfs", "listSnapshots", "/System/Volumes/Data", "-plist"], plistlib.loads)
    elif system == "Linux":
        disks = command(["lsblk", "--json", "--bytes", "--output",
                         "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINTS"], json.loads)
        if "error" in disks:
            # Older util-linux releases have MOUNTPOINT rather than MOUNTPOINTS.
            disks = command(["lsblk", "--json", "--bytes", "--output",
                             "NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT"], json.loads)
        result["commands"]["disks"] = disks
        result["partitions"] = linux_rows(disks.get("data", {}))
        result["commands"]["mounts"] = command(["findmnt", "--json", "--bytes", "--output",
                                                "TARGET,SOURCE,FSTYPE,SIZE,USED,AVAIL"], json.loads)
    return result


def default_roots():
    home = str(Path.home())
    if platform.system() == "Darwin":
        paths = [home, "/Library", "/Applications", "/opt", "/private/var", "/Users/Shared"]
    else:
        paths = [home, "/var", "/usr", "/opt", "/nix", "/srv"]
    return [p for p in paths if os.path.lexists(p)]


def normalize_paths(paths, collapse=True):
    # Lexical normalization avoids resolving symlinks or contacting a remote mount.
    values = sorted(set(os.path.abspath(os.path.expanduser(p)) for p in paths), key=len)
    roots = []
    for path in values:
        if not collapse or not any(os.path.commonpath([path, root]) == root for root in roots):
            roots.append(path)
    return roots
