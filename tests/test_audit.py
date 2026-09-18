import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import mock_open, patch

from disk_audit.cli import ranked, rollups, safe
from disk_audit.scan import Scanner, advice, linux_mountpoints, scan
from disk_audit.system import command, linux_rows, mac_rows, normalize_paths


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def measure(self, path=None, discover=False, exclusions=()):
        messages = []
        Scanner(messages.append, minimum=1, top=50, exclusions=exclusions).run(
            str(path or self.root), discover)
        return messages[-1]["result"], messages

    def test_allocated_size_and_hardlinks(self):
        file = self.root / "data"
        file.write_bytes(b"x" * 8192)
        os.link(file, self.root / "second-name")
        result, _ = self.measure()
        expected = file.stat().st_blocks * 512 + self.root.stat().st_blocks * 512
        self.assertEqual(result["allocated_bytes"], expected)
        self.assertEqual(result["files_seen"], 1)

    def test_sparse_file_is_not_virtual_capacity(self):
        file = self.root / "virtual-disk"
        with file.open("wb") as stream:
            stream.truncate(1_000_000_000)
        result, _ = self.measure()
        self.assertEqual(result["apparent_bytes"], 1_000_000_000)
        self.assertLess(result["allocated_bytes"], 1_000_000)

    def test_symlink_and_fifo_not_followed(self):
        (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root / "pipe")
        result, _ = self.measure()
        self.assertEqual(result["symlinks_skipped"], 1)
        self.assertEqual(result["files_seen"], 0)
        self.assertEqual(result["status"], "complete")

    def test_symlink_root_not_followed(self):
        link = self.root / "link"
        link.symlink_to(self.root, target_is_directory=True)
        result, _ = self.measure(link)
        self.assertEqual(result["allocated_bytes"], 0)
        self.assertEqual(result["symlinks_skipped"], 1)

    def test_nested_mount_is_skipped(self):
        folder = self.root / "mounted"
        folder.mkdir()
        (folder / "data").write_bytes(b"x" * 8192)
        with patch("disk_audit.scan.os.path.ismount", side_effect=lambda p: p == str(folder)):
            result, _ = self.measure()
        self.assertEqual(result["mounts_skipped"], 1)
        self.assertEqual(result["files_seen"], 0)

    def test_linux_bind_mountinfo(self):
        fixture = "50 20 8:1 /data /mnt/bind\\040data rw - ext4 /dev/sda1 rw\n"
        with patch("builtins.open", mock_open(read_data=fixture)):
            self.assertEqual(linux_mountpoints(), {"/mnt/bind data"})
        folder = self.root / "bind"
        folder.mkdir()
        (folder / "payload").write_bytes(b"x" * 8192)
        with patch("disk_audit.scan.linux_mountpoints", return_value={str(folder)}):
            result, _ = self.measure()
        self.assertEqual(result["mounts_skipped"], 1)
        self.assertEqual(result["files_seen"], 0)

    def test_explicit_nested_roots_are_not_double_scanned(self):
        child = self.root / "child"
        child.mkdir()
        file = child / "file"
        file.write_bytes(b"x" * 8192)
        results, _ = scan([str(self.root), str(child)], 1, 10, 2, 5, 10)
        self.assertEqual(sum(r.get("files_seen", 0) for r in results), 1)

    def test_explicit_file_is_not_reported_as_directory(self):
        file = self.root / "payload"
        file.write_bytes(b"x" * 8192)
        results, _ = scan([str(file)], 1, 10, 1, 5, 10)
        self.assertFalse(results[0]["discovery_only"])
        self.assertEqual(rollups(results, 1)["large_directories"], [])

    def test_permission_failure_is_not_empty_success(self):
        with patch("disk_audit.scan.os.scandir", side_effect=PermissionError("denied")):
            result, _ = self.measure()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["error_count"], 1)

    def test_discovery_counts_loose_files_and_emits_children(self):
        folder = self.root / "child"
        folder.mkdir()
        (self.root / "loose").write_bytes(b"x" * 8192)
        (folder / "nested").write_bytes(b"x" * 16384)
        result, messages = self.measure(discover=True)
        self.assertEqual(result["files_seen"], 1)
        self.assertIn({"kind": "child", "path": str(folder)}, messages)

    def test_excluded_subtree_not_scanned(self):
        folder = self.root / "private"
        folder.mkdir()
        (folder / "large").write_bytes(b"x" * 8192)
        result, _ = self.measure(exclusions=[str(folder)])
        self.assertEqual(result["files_seen"], 0)
        self.assertEqual(result["excluded"], 1)

    def test_nomachine_is_not_javascript_nx(self):
        self.assertIsNone(advice("/home/a/.nx/project/cache", True))
        hint = advice("/home/a/.nx/node/F-C-machine-123/session", False)
        self.assertEqual(hint[0], "old session log")
        self.assertIsNone(advice("/home/a/.nx/node/C-active/session", False))

    def test_supervisor_completes_and_does_not_modify_files(self):
        folder = self.root / "data"
        folder.mkdir()
        file = folder / "payload"
        file.write_bytes(b"x" * 8192)
        before = (file.read_bytes(), file.stat().st_mtime_ns)
        results, interrupted = scan([str(self.root)], 1, 10, 2, 5, 10)
        self.assertFalse(interrupted)
        self.assertTrue(all(r["status"] == "complete" for r in results))
        self.assertEqual(before, (file.read_bytes(), file.stat().st_mtime_ns))
        self.assertEqual(ranked(results, "large_files", 5)[0]["path"], str(file))

    def test_worker_timeout_is_bounded_and_explicit(self):
        # A deadline shorter than spawn startup must not be reported as an empty success.
        started = time.monotonic()
        results, _ = scan([str(self.root)], 1, 5, 1, 0.000001, 5)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(results[0]["status"], "timeout")

    def test_total_budget_marks_unstarted_work(self):
        results, _ = scan([str(self.root)], 1, 5, 1, 5, 0.000000001)
        self.assertEqual(results[0]["status"], "not_scanned")

    def test_macos_physical_partitions_not_synthesized_totals(self):
        disks = {"AllDisksAndPartitions": [
            {"Content": "GUID_partition_scheme", "DeviceIdentifier": "disk0", "Size": 1000,
             "Partitions": [{"DeviceIdentifier": "disk0s2", "Content": "Apple_APFS", "Size": 600,
                             "APFSContainerReference": "disk3"}]},
            {"Content": "Apple_APFS", "DeviceIdentifier": "disk3", "Size": 600}]}
        apfs = {"Containers": [{"ContainerReference": "disk3", "CapacityFree": 25,
                                "Volumes": [{"Name": "Data"}]}]}
        rows = mac_rows(disks, apfs)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["free_bytes"], 25)

    def test_linux_lvm_nesting_preserved(self):
        rows = linux_rows({"blockdevices": [{"name": "nvme0n1", "type": "disk", "size": 1000,
                           "children": [{"name": "nvme0n1p1", "type": "part", "size": 900,
                                         "children": [{"name": "root", "type": "lvm", "size": 800}]}]}]})
        self.assertEqual([x["level"] for x in rows], [0, 1, 2])

    def test_macos_actual_physical_store_mapping(self):
        disks = {"AllDisksAndPartitions": [{"Content": "GUID_partition_scheme", "DeviceIdentifier": "disk0",
                 "Partitions": [{"DeviceIdentifier": "disk0s3", "Size": 38_000_000_000}]}]}
        apfs = {"Containers": [{"ContainerReference": "disk4", "CapacityFree": 37_000_000_000,
                "PhysicalStores": [{"DeviceIdentifier": "disk0s3"}]}]}
        self.assertEqual(mac_rows(disks, apfs)[1]["free_bytes"], 37_000_000_000)

    def test_rollups_include_partial_descendants_once(self):
        summaries = rollups([
            {"path": "/home/a", "allocated_bytes": 10, "status": "complete", "discovery_only": True},
            {"path": "/home/a/Library", "allocated_bytes": 20, "status": "complete", "discovery_only": True},
            {"path": "/home/a/Library/Caches", "allocated_bytes": 30, "status": "timeout"},
            {"path": "/home/a/Code", "allocated_bytes": 40, "status": "complete"}], 1)
        home = next(x for x in summaries["large_directories"] if x["path"] == "/home/a")
        self.assertEqual(home["allocated_bytes"], 100)
        self.assertFalse(home["complete"])

    def test_command_failure_and_timeout(self):
        self.assertIn("error", command(["/nonexistent/disk-audit-command"]))
        with patch("disk_audit.system.subprocess.run", side_effect=subprocess.TimeoutExpired("lsblk", 1)):
            self.assertIn("error", command(["lsblk"]))

    def test_overlap_normalization_and_terminal_sanitizing(self):
        self.assertEqual(normalize_paths(["/tmp/a/b", "/tmp/a", "/tmp/abc"]), ["/tmp/a", "/tmp/abc"])
        self.assertNotIn("\x1b", safe("bad\x1b[31m\npath"))

    def test_cli_json_and_strict_missing_path(self):
        result = subprocess.run([sys.executable, "-m", "disk_audit", "--path", str(self.root / "missing"),
                                 "--format", "json", "--no-system", "--quiet", "--strict"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        data = json.loads(result.stdout)
        self.assertEqual(data["scans"][0]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
