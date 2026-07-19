# Copyright 2026 Gateway Information Group LLC. All rights reserved.
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import time
import zipfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

import bot_manager as bm  # noqa: E402


class IsolatedAppMixin:
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.manager_root = self.base / "manager"
        self.manager_root.mkdir()
        self.app_patch = mock.patch.object(bm, "app_root", return_value=self.manager_root)
        self.app_patch.start()
        bm._PROCESS_CACHE = (0.0, bm.ProcessInventory())
        bm._LOG_CANDIDATE_CACHE.clear()
        if bm._LOGGER is not None:
            for handler in list(bm._LOGGER.handlers):
                handler.close()
                bm._LOGGER.removeHandler(handler)
        bm._LOGGER = None

    def tearDown(self) -> None:
        if bm._LOGGER is not None:
            for handler in list(bm._LOGGER.handlers):
                handler.close()
                bm._LOGGER.removeHandler(handler)
        bm._LOGGER = None
        self.app_patch.stop()
        self.temp.cleanup()

    def config_for(self, bots_root: Path) -> dict:
        cfg = copy.deepcopy(bm.DEFAULT_CONFIG)
        cfg["bots_root"] = str(bots_root)
        cfg["log_cache_seconds"] = 0
        cfg["process_cache_seconds"] = 0
        return cfg

    def complete_inventory(self, *processes: bm.ProcessInfo) -> bm.ProcessInventory:
        return bm.ProcessInventory(processes, complete=True, source="test-complete")


class LauncherSafetyTests(IsolatedAppMixin, unittest.TestCase):
    def test_unsafe_start_scripts_are_blocked_and_stop_is_separate(self) -> None:
        folder = self.base / "PolicyService_Production"
        folder.mkdir()
        for name in (
            "EMERGENCY_STOP_POLICY_SERVICE.bat",
            "RUN_EXPORT_TO_SUPPORT.bat",
            "build_policy_service_bot.bat",
            "start_primary_worker.bat",
        ):
            (folder / name).write_text("@echo off\n", encoding="utf-8")

        starts, stops = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        selected = next(item for item in starts if not item.blocked and item.score >= 35)
        self.assertEqual(Path(selected.path).name, "start_primary_worker.bat")

        emergency_start = next(item for item in starts if "EMERGENCY_STOP" in item.path)
        self.assertTrue(emergency_start.blocked)
        selected_stop = next(item for item in stops if not item.blocked and item.score >= 50)
        self.assertEqual(Path(selected_stop.path).name, "EMERGENCY_STOP_POLICY_SERVICE.bat")

    def test_native_worker_build_script_loses_to_runtime_executable(self) -> None:
        folder = self.base / "NativeWorkerPackage"
        folder.mkdir()
        (folder / "build_native_worker.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "native_worker.exe").write_bytes(b"MZ")

        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(Path(path).name, "native_worker.exe")
        self.assertEqual(kind, "executable")

    def test_neutral_data_worker_launcher_matches_folder_name(self) -> None:
        folder = self.base / "DataWorker"
        folder.mkdir()
        (folder / "worker_console.bat").write_text("@echo off\n", encoding="utf-8")

        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(Path(path).name, "worker_console.bat")
        self.assertEqual(kind, "batch")


    def test_data_worker_common_module_is_not_preferred_over_bat_control(self) -> None:
        folder = self.base / "DataWorker"
        folder.mkdir()
        (folder / "data_worker_bot_common.py").write_text("# shared helpers only\n", encoding="utf-8")
        (folder / "worker_console.bat").write_text("@echo off\n", encoding="utf-8")

        starts, _ = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        common = next(item for item in starts if Path(item.path).name == "data_worker_bot_common.py")
        self.assertTrue(common.blocked)
        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(Path(path).name, "worker_console.bat")
        self.assertEqual(kind, "batch")

    def test_collection_folder_is_split_into_nested_bots_not_mixed_launcher_scope(self) -> None:
        bots_root = self.base / "Bots"
        alpha = bots_root / "Workers" / "Alpha"
        beta = bots_root / "Workers" / "Beta"
        alpha.mkdir(parents=True)
        beta.mkdir(parents=True)
        (alpha / "worker_status.ps1").write_text("# status only\n", encoding="utf-8")
        (alpha / "start_alpha_worker.bat").write_text("@echo off\n", encoding="utf-8")
        (beta / "start-worker.bat").write_text("@echo off\n", encoding="utf-8")
        (beta / "stop-worker.bat").write_text("@echo off\n", encoding="utf-8")

        bots = bm.scan_bots(self.config_for(bots_root), save=False)
        self.assertNotIn("Workers", bots)
        self.assertIn("Workers__Alpha", bots)
        self.assertIn("Workers__Beta", bots)
        self.assertEqual(Path(bots["Workers__Alpha"].launcher).name, "start_alpha_worker.bat")
        self.assertEqual(Path(bots["Workers__Beta"].launcher).name, "start-worker.bat")
        self.assertEqual(Path(bots["Workers__Beta"].stop_launcher).name, "stop-worker.bat")

    def test_nested_stop_from_different_child_scope_is_not_auto_selected(self) -> None:
        folder = self.base / "Workers"
        (folder / "Alpha").mkdir(parents=True)
        (folder / "Beta").mkdir(parents=True)
        (folder / "Alpha" / "start_alpha_worker.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "Beta" / "stop-worker.bat").write_text("@echo off\n", encoding="utf-8")
        starts, stops = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        safe_auto = next(item for item in starts if not item.blocked and item.score >= 60)
        safe_stop = next(
            (
                item
                for item in stops
                if not item.blocked
                and item.score >= 50
                and bm.stop_scope_matches_start(folder, safe_auto.path, item.path)
            ),
            None,
        )
        self.assertIsNone(safe_stop)

    def test_package_json_with_start_script_is_allowed_and_uses_prefix(self) -> None:
        folder = self.base / "NodeWorker"
        package_dir = folder / "ui"
        package_dir.mkdir(parents=True)
        package = package_dir / "package.json"
        package.write_text(json.dumps({"scripts": {"start": "node index.js"}}), encoding="utf-8")

        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(Path(path), package)
        self.assertEqual(kind, "npm")
        command = bm.build_runner_command_path(package, kind, folder, self.config_for(self.base))
        self.assertIn("npm --prefix", command)
        self.assertIn(str(package_dir), command)

    def test_package_json_without_start_script_is_blocked(self) -> None:
        folder = self.base / "NodeWorker"
        folder.mkdir()
        package = folder / "package.json"
        package.write_text(json.dumps({"scripts": {"test": "echo test"}}), encoding="utf-8")
        candidate = bm.score_start_candidate(package, folder, self.config_for(self.base))
        self.assertTrue(candidate.blocked)

    def test_generic_helper_script_is_not_automatic_launcher(self) -> None:
        folder = self.base / "MysteryBot"
        folder.mkdir()
        (folder / "config.py").write_text("SETTINGS = {}\n", encoding="utf-8")
        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(path, "")
        self.assertEqual(kind, "none")


    def test_cascade_manager_launchers_are_monitor_only_not_auto_start(self) -> None:
        # Keep this distinct from the lowercase isolated manager directory on
        # case-insensitive Windows filesystems.
        folder = self.base / "CascadeManager"
        folder.mkdir()
        (folder / "start_all_bots_from_manager.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "clear_all_stop_requests.bat").write_text("@echo off\n", encoding="utf-8")

        bots = bm.scan_bots(self.config_for(self.base), save=False)
        manager = bots["CascadeManager"]

        self.assertEqual(manager.category, "manager")
        self.assertEqual(manager.launcher, "")
        self.assertFalse(manager.launcher_safe)
        self.assertEqual(manager.stop_launcher, "")

        starts, _ = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        start_all = next(item for item in starts if Path(item.path).name == "start_all_bots_from_manager.bat")
        clear_all = bm.score_stop_candidate(folder / "clear_all_stop_requests.bat", folder, self.config_for(self.base))
        self.assertTrue(start_all.blocked)
        self.assertTrue(clear_all.blocked)


    def test_broad_local_bots_stop_script_is_not_auto_selected(self) -> None:
        folder = self.base / "PolicyService-bot"
        folder.mkdir()
        (folder / "START_HERE_POLICY_BOT.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "R289_STOP_LOCAL_BOTS_AND_CLEAN_LOCKS.bat").write_text("@echo off\n", encoding="utf-8")

        starts, _ = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        broad_stop = bm.score_stop_candidate(folder / "R289_STOP_LOCAL_BOTS_AND_CLEAN_LOCKS.bat", folder, self.config_for(self.base))
        self.assertTrue(broad_stop.blocked)
        self.assertIn("blocked stop terms", "; ".join(broad_stop.reasons))
        self.assertTrue(any(not item.blocked for item in starts))

    def test_task_exit_and_reconciliation_are_not_auto_stop_handlers(self) -> None:
        folder = self.base / "PolicyService_Production"
        folder.mkdir()
        for name in ("active_task_exit.py", "policy_service_post_stop_reconciliation.py"):
            (folder / name).write_text("# not a process-control stop script\n", encoding="utf-8")

        active = bm.score_stop_candidate(folder / "active_task_exit.py", folder, self.config_for(self.base))
        reconciliation = bm.score_stop_candidate(folder / "policy_service_post_stop_reconciliation.py", folder, self.config_for(self.base))
        self.assertTrue(active.blocked)
        self.assertTrue(reconciliation.blocked)

    def test_schedule_worker_folders_are_worker_category_not_unknown(self) -> None:
        folder = self.base / "schedule_worker_15m_rebuild"
        folder.mkdir()
        (folder / "schedule_worker_15m_v67.py").write_text("# worker\n", encoding="utf-8")
        bots = bm.scan_bots(self.config_for(self.base), save=False)
        self.assertEqual(bots["schedule_worker_15m_rebuild"].category, "worker")

    def test_schedule_worker_command_center_bat_wins_over_raw_engine(self) -> None:
        folder = self.base / "schedule_worker_15m"
        folder.mkdir()
        (folder / "CONTROL_CENTER.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "schedule_worker_15m_v67.py").write_text("# raw runtime engine\n", encoding="utf-8")

        path, kind = bm.detect_launcher(folder, self.config_for(self.base))

        self.assertEqual(Path(path).name, "CONTROL_CENTER.bat")
        self.assertEqual(kind, "batch")

    def test_sidecar_launch_helpers_are_not_auto_start_candidates(self) -> None:
        folder = self.base / "data_worker_collection"
        sidecar = folder / "data_worker_sidecars"
        sidecar.mkdir(parents=True)
        (folder / "worker_console.bat").write_text("@echo off\n", encoding="utf-8")
        helper = sidecar / "data_worker_launch_auxiliary_service.py"
        helper.write_text("# sidecar helper, not a primary launcher\n", encoding="utf-8")

        starts, _ = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        sidecar_candidate = next(item for item in starts if Path(item.path).name == helper.name)

        self.assertTrue(sidecar_candidate.blocked)
        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        self.assertEqual(Path(path).name, "worker_console.bat")
        self.assertEqual(kind, "batch")

    def test_stop_test_files_are_blocked_even_when_they_contain_close_terms(self) -> None:
        folder = self.base / "schedule_worker_15m"
        tests_dir = folder / "tests"
        tests_dir.mkdir(parents=True)
        test_file = tests_dir / "v67_68_postclose_rollup_guard_test.py"
        test_file.write_text("# test only\n", encoding="utf-8")

        candidate = bm.score_stop_candidate(test_file, folder, self.config_for(self.base))

        self.assertTrue(candidate.blocked)
        self.assertIn("blocked stop terms", "; ".join(candidate.reasons))

    def test_selftest_does_not_warn_for_monitor_only_utility_folders(self) -> None:
        bots_root = self.base / "Bots"
        document_utility = bots_root / "DocumentUtility_v1.1.0"
        network_utility = bots_root / "NetworkUtility_v2.2.0"
        service = bots_root / "MysteryService"
        document_utility.mkdir(parents=True)
        network_utility.mkdir(parents=True)
        service.mkdir(parents=True)
        (document_utility / "requirements.txt").write_text("# utility marker\n", encoding="utf-8")
        (network_utility / "requirements.txt").write_text("# utility marker\n", encoding="utf-8")
        (service / "requirements.txt").write_text("# bot marker\n", encoding="utf-8")

        cfg = self.config_for(bots_root)
        with mock.patch.object(bm, "get_processes", return_value=[]), mock.patch.object(bm, "process_inventory_reliable", return_value=False):
            bots = bm.scan_bots(cfg, save=False)
            result = bm.run_selftest(cfg, bots)

        coverage = next(item for item in result["checks"] if item["name"] == "Start launcher coverage")
        self.assertEqual(bots["DocumentUtility_v1.1.0"].category, "utility")
        self.assertEqual(bots["NetworkUtility_v2.2.0"].category, "utility")
        self.assertEqual(coverage["status"], "WARN")
        self.assertIn("MysteryService", coverage["detail"])
        self.assertNotIn("DocumentUtility", coverage["detail"])
        self.assertNotIn("NetworkUtility", coverage["detail"])

    def test_extracted_botops_release_folders_are_ignored_by_pattern(self) -> None:
        bots_root = self.base / "Bots"
        real = bots_root / "RealBot"
        stale = bots_root / "BotOps_Manager_v9.9.9"
        real.mkdir(parents=True)
        stale.mkdir(parents=True)
        (real / "start.bat").write_text("@echo off\n", encoding="utf-8")
        (stale / "start.bat").write_text("@echo off\n", encoding="utf-8")

        bots = bm.scan_bots(self.config_for(bots_root), save=False)

        self.assertIn("RealBot", bots)
        self.assertNotIn("BotOps_Manager_v9.9.9", bots)

    def test_missing_bots_root_does_not_rewrite_registry_to_empty(self) -> None:
        missing_root = self.base / "MovedBots"
        cfg = self.config_for(missing_root)
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {
                "OldBot": {
                    "name": "OldBot",
                    "path": str(self.base / "OldBot"),
                    "launcher": "",
                }
            },
        }
        bm.registry_path().write_text(json.dumps(original, indent=2), encoding="utf-8")

        bots = bm.scan_bots(cfg, save=True)

        self.assertIn("OldBot", bots)
        self.assertEqual(json.loads(bm.registry_path().read_text(encoding="utf-8")), original)

    def test_unsafe_existing_bots_root_does_not_rewrite_manager_state(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        registry_original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"name": "OldBot", "path": str(self.base / "OldBot"), "launcher": ""}},
        }
        runtime_original = {
            "version": bm.RUNTIME_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"roots": []}},
        }
        health_original = {
            "version": bm.HEALTH_STATE_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"samples": []}},
        }
        bm.registry_path().write_text(json.dumps(registry_original, indent=2), encoding="utf-8")
        bm.runtime_state_path().write_text(json.dumps(runtime_original, indent=2), encoding="utf-8")
        bm.health_state_path().write_text(json.dumps(health_original, indent=2), encoding="utf-8")
        original_link_check = bm.path_is_reparse_or_symlink

        def root_looks_linked(path: Path) -> bool:
            return Path(path) == bots_root or original_link_check(Path(path))

        with mock.patch.object(bm, "path_is_reparse_or_symlink", side_effect=root_looks_linked):
            bots = bm.scan_bots(cfg, save=True)

        self.assertIn("OldBot", bots)
        self.assertEqual(json.loads(bm.registry_path().read_text(encoding="utf-8")), registry_original)
        self.assertEqual(json.loads(bm.runtime_state_path().read_text(encoding="utf-8")), runtime_original)
        self.assertEqual(json.loads(bm.health_state_path().read_text(encoding="utf-8")), health_original)

    def test_root_enumeration_failure_preserves_all_manager_state(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"name": "OldBot", "path": str(self.base / "OldBot"), "launcher": ""}},
        }
        bm.registry_path().write_text(json.dumps(original, indent=2), encoding="utf-8")
        real_iterdir = Path.iterdir

        def fail_root_iteration(path: Path):
            if Path(path) == bots_root:
                raise PermissionError("synthetic root traversal failure")
            return real_iterdir(path)

        with mock.patch.object(Path, "iterdir", fail_root_iteration), mock.patch.object(
            bm, "write_registry"
        ) as write_registry, mock.patch.object(bm, "prune_runtime_state") as prune_runtime, mock.patch.object(
            bm, "prune_health_state"
        ) as prune_health:
            bots = bm.scan_bots(self.config_for(bots_root), save=True)

        self.assertIn("OldBot", bots)
        write_registry.assert_not_called()
        prune_runtime.assert_not_called()
        prune_health.assert_not_called()

    def test_nested_traversal_failure_preserves_all_manager_state(self) -> None:
        bots_root = self.base / "Bots"
        collection = bots_root / "Collection"
        collection.mkdir(parents=True)
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"name": "OldBot", "path": str(self.base / "OldBot"), "launcher": ""}},
        }
        bm.registry_path().write_text(json.dumps(original, indent=2), encoding="utf-8")
        real_walk = bm.os.walk

        def fail_collection_walk(top, *args, **kwargs):
            if Path(top) == collection:
                onerror = kwargs.get("onerror")
                if onerror is not None:
                    onerror(PermissionError("synthetic nested traversal failure"))
                return iter(())
            return real_walk(top, *args, **kwargs)

        with mock.patch.object(bm.os, "walk", side_effect=fail_collection_walk), mock.patch.object(
            bm, "write_registry"
        ) as write_registry, mock.patch.object(bm, "prune_runtime_state") as prune_runtime, mock.patch.object(
            bm, "prune_health_state"
        ) as prune_health:
            bots = bm.scan_bots(self.config_for(bots_root), save=True)

        self.assertIn("OldBot", bots)
        write_registry.assert_not_called()
        prune_runtime.assert_not_called()
        prune_health.assert_not_called()

    def test_child_safety_failure_after_root_preflight_preserves_manager_state(self) -> None:
        bots_root = self.base / "Bots"
        child = bots_root / "TemporarilyInaccessibleBot"
        child.mkdir(parents=True)
        (child / "start.bat").write_text("@echo off\n", encoding="utf-8")
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"name": "OldBot", "path": str(self.base / "OldBot"), "launcher": ""}},
        }
        bm.registry_path().write_text(json.dumps(original, indent=2), encoding="utf-8")
        real_safety_check = bm.directory_is_safe_within

        def fail_child_safety(path: Path, root: Path) -> bool:
            if Path(path) == child and Path(root) == bots_root:
                return False
            return real_safety_check(Path(path), Path(root))

        with mock.patch.object(bm, "directory_is_safe_within", side_effect=fail_child_safety), mock.patch.object(
            bm, "write_registry"
        ) as write_registry, mock.patch.object(bm, "prune_runtime_state") as prune_runtime, mock.patch.object(
            bm, "prune_health_state"
        ) as prune_health:
            bots = bm.scan_bots(self.config_for(bots_root), save=True)

        self.assertIn("OldBot", bots)
        write_registry.assert_not_called()
        prune_runtime.assert_not_called()
        prune_health.assert_not_called()

    def test_launcher_candidate_cap_preserves_manager_state(self) -> None:
        bots_root = self.base / "Bots"
        child = bots_root / "ManyLaunchersBot"
        child.mkdir(parents=True)
        (child / "start_one.bat").write_text("@echo off\n", encoding="utf-8")
        (child / "start_two.bat").write_text("@echo off\n", encoding="utf-8")
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "known-good",
            "bots": {"OldBot": {"name": "OldBot", "path": str(self.base / "OldBot"), "launcher": ""}},
        }
        bm.registry_path().write_text(json.dumps(original, indent=2), encoding="utf-8")
        cfg = self.config_for(bots_root)
        cfg["max_launcher_candidates_per_bot"] = 1

        with mock.patch.object(bm, "write_registry") as write_registry, mock.patch.object(
            bm, "prune_runtime_state"
        ) as prune_runtime, mock.patch.object(bm, "prune_health_state") as prune_health:
            bots = bm.scan_bots(cfg, save=True)

        self.assertIn("OldBot", bots)
        write_registry.assert_not_called()
        prune_runtime.assert_not_called()
        prune_health.assert_not_called()

    def test_path_targeting_report_records_root_source_and_missing_guard(self) -> None:
        missing_root = self.base / "MissingRoot"
        cfg = self.config_for(missing_root)
        cfg["_bots_root_source"] = "BOTOPS_BOTS_ROOT"

        report = bm.build_path_targeting_report(cfg, {})

        self.assertEqual(report["bots_root_source"], "BOTOPS_BOTS_ROOT")
        self.assertFalse(report["exists"])
        self.assertEqual(report["scan_write_guard"], "enabled_no_rewrite_when_root_missing")
        self.assertTrue(any("does not exist" in item for item in report["findings"]))

    def test_path_text_within_canonicalizes_parent_traversal(self) -> None:
        self.assertTrue(bm.path_text_within(r"C:\Bots", r"C:\Bots\Worker"))
        self.assertFalse(bm.path_text_within(r"C:\Bots", r"C:\Bots\..\Sensitive"))
        self.assertFalse(bm.path_text_within(r"C:\Bots", r"D:\Bots\Worker"))

    def test_reparse_like_child_directory_is_not_discovered(self) -> None:
        bots_root = self.base / "Bots"
        linked = bots_root / "LinkedWorker"
        linked.mkdir(parents=True)
        (linked / "start.bat").write_text("@echo off\n", encoding="utf-8")
        original = bm.path_is_reparse_or_symlink

        def looks_linked(path: Path) -> bool:
            return Path(path) == linked or original(Path(path))

        with mock.patch.object(bm, "path_is_reparse_or_symlink", side_effect=looks_linked):
            bots = bm.scan_bots(self.config_for(bots_root), save=False)
        self.assertNotIn("LinkedWorker", bots)

    def test_stale_launcher_priority_config_still_prefers_control_center_wrapper(self) -> None:
        folder = self.base / "schedule_worker_15m"
        folder.mkdir()
        (folder / "CONTROL_CENTER.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "schedule_worker_15m_v67.py").write_text("# raw runtime engine\n", encoding="utf-8")
        cfg = self.config_for(self.base)
        cfg["launcher_priority"] = [
            "start.bat",
            "run.bat",
            "launch.bat",
            "bot.bat",
            "start.cmd",
            "run.cmd",
            "launch.cmd",
            "start.ps1",
            "run.ps1",
            "main.py",
            "bot.py",
            "worker.py",
            "service.py",
            "app.py",
            "__main__.py",
            "index.js",
            "server.js",
            "package.json",
            "control_center.bat",
            "service_console.bat",
        ]

        path, kind = bm.detect_launcher(folder, cfg)

        self.assertEqual(Path(path).name, "CONTROL_CENTER.bat")
        self.assertEqual(kind, "batch")

    def test_config_migration_promotes_current_launcher_priority_defaults(self) -> None:
        cfg = self.config_for(self.base)
        cfg["launcher_priority"] = ["bot.bat", "main.py", "control_center.bat"]

        migrated = bm._coerce_config(cfg)

        self.assertLess(migrated["launcher_priority"].index("control_center.bat"), migrated["launcher_priority"].index("bot.bat"))
        self.assertLess(migrated["launcher_priority"].index("worker_console.bat"), migrated["launcher_priority"].index("bot.bat"))

    def test_project_identity_terms_allow_exact_root_wrappers(self) -> None:
        utility = self.base / "SupportUtility"
        tools = utility / "tools"
        tools.mkdir(parents=True)
        (utility / "SupportUtility.bat").write_text("@echo off\n", encoding="utf-8")
        (tools / "support_utility.py").write_text("# implementation module\n", encoding="utf-8")

        path, kind = bm.detect_launcher(utility, self.config_for(self.base))
        starts, _ = bm.audit_launcher_candidates(utility, self.config_for(self.base))
        module = next(item for item in starts if Path(item.path).name == "support_utility.py")

        self.assertEqual(Path(path).name, "SupportUtility.bat")
        self.assertEqual(kind, "batch")
        self.assertTrue(module.blocked)

    def test_network_utility_identity_bat_allowed_report_helper_blocked(self) -> None:
        folder = self.base / "NetworkUtility"
        folder.mkdir()
        (folder / "NetworkUtility.bat").write_text("@echo off\n", encoding="utf-8")
        (folder / "NetworkUtility.ps1").write_text("Write-Host run\n", encoding="utf-8")
        (folder / "Compare-NetworkUtilityReports.ps1").write_text("Write-Host compare\n", encoding="utf-8")

        path, kind = bm.detect_launcher(folder, self.config_for(self.base))
        starts, _ = bm.audit_launcher_candidates(folder, self.config_for(self.base))
        report_helper = next(item for item in starts if Path(item.path).name == "Compare-NetworkUtilityReports.ps1")

        self.assertEqual(Path(path).name, "NetworkUtility.bat")
        self.assertEqual(kind, "batch")
        self.assertTrue(report_helper.blocked)


class HealthSelectionTests(IsolatedAppMixin, unittest.TestCase):
    def test_operational_log_beats_newer_export_version_and_support_files(self) -> None:
        folder = self.base / "EventWorker"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        operational = logs / "events.jsonl"
        operational.write_text('{"event":"heartbeat"}\n', encoding="utf-8")
        bad_files = [
            folder / "PASTE_HEALTH_TO_SUPPORT.txt",
            folder / "VERSION.txt",
            folder / "latest_r247_support_export_compiler.txt",
        ]
        for path in bad_files:
            path.write_text("not a runtime heartbeat\n", encoding="utf-8")

        old = time.time() - 120
        os.utime(operational, (old, old))
        now = time.time()
        for index, path in enumerate(bad_files):
            os.utime(path, (now + index, now + index))

        bot = bm.BotRecord(name=folder.name, path=str(folder))
        selected = bm.select_health_candidate(bot, self.config_for(self.base))
        self.assertIsNotNone(selected)
        self.assertEqual(Path(selected.path), operational)
        for path in bad_files:
            scored = bm.score_log_candidate(path, folder, self.config_for(self.base))
            self.assertFalse(scored.reliable, path.name)

    def test_manual_heartbeat_must_stay_inside_bot_folder(self) -> None:
        folder = self.base / "Bot"
        folder.mkdir()
        outside = self.base / "outside.log"
        outside.write_text("heartbeat\n", encoding="utf-8")
        bot = bm.BotRecord(
            name="Bot",
            path=str(folder),
            heartbeat_file=str(outside),
            heartbeat_manual=True,
        )
        self.assertIsNone(bm.select_health_candidate(bot, self.config_for(self.base)))


    def test_export_handoff_log_is_rejected_even_with_log_extension(self) -> None:
        folder = self.base / "PC_Improve"
        exported = folder / "exports_for_support"
        exported.mkdir(parents=True)
        path = exported / "ZIP_CREATION_ATTEMPTS_20260709_055433.log"
        path.write_text("archive attempt\n", encoding="utf-8")
        cfg = self.config_for(self.base)

        candidate = bm.score_log_candidate(path, folder, cfg)
        bot = bm.BotRecord(name=folder.name, path=str(folder))

        self.assertFalse(candidate.reliable)
        self.assertEqual(candidate.tier, "none")
        self.assertTrue(any("excluded non-runtime directory" in reason for reason in candidate.reasons))
        self.assertIsNone(bm.select_health_candidate(bot, cfg))

    def test_semantic_launcher_logs_directory_is_strong_evidence(self) -> None:
        folder = self.base / "data_worker_collection"
        logs = folder / "launcher_logs"
        logs.mkdir(parents=True)
        path = logs / "BTC-USD_latest.log"
        path.write_text("runtime progress\n", encoding="utf-8")

        candidate = bm.score_log_candidate(path, folder, self.config_for(self.base))

        self.assertTrue(candidate.reliable)
        self.assertEqual(candidate.tier, "strong")
        self.assertTrue(any("log/runtime directory" in reason for reason in candidate.reasons))

    def test_unstatable_candidate_cannot_mask_timestamped_evidence(self) -> None:
        cfg = self.config_for(self.base)
        bot = bm.BotRecord(name="StatBot", path=str(self.base / "StatBot"))
        unavailable = bm.LogCandidate(
            "logs/unavailable.log", 90, True, None, [], "strong", "logs/unavailable.log"
        )
        timestamped = bm.LogCandidate(
            "runtime.log", 40, True, 1000.0, [], "standard", "runtime.log"
        )

        selected = bm.select_health_candidate(
            bot, cfg, now=1000.0, candidates=[unavailable, timestamped]
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected.path, "runtime.log")

    def test_provenance_wins_within_freshness_window_but_not_indefinitely(self) -> None:
        cfg = self.config_for(self.base)
        cfg["stale_minutes"] = 10
        bot = bm.BotRecord(name="RankedBot", path=str(self.base / "RankedBot"))
        standard = bm.LogCandidate("root.log", 40, True, 2000.0, [], "standard", "root.log")
        strong_near = bm.LogCandidate("logs/runtime.log", 65, True, 1500.0, [], "strong", "logs/runtime.log")
        strong_old = bm.LogCandidate("logs/runtime.log", 65, True, 1300.0, [], "strong", "logs/runtime.log")

        selected_near = bm.select_health_candidate(
            bot, cfg, now=2000.0, candidates=[standard, strong_near]
        )
        selected_old = bm.select_health_candidate(
            bot, cfg, now=2000.0, candidates=[standard, strong_old]
        )

        self.assertIsNotNone(selected_near)
        self.assertIsNotNone(selected_old)
        self.assertEqual(selected_near.tier, "strong")
        self.assertEqual(selected_old.tier, "standard")

    def test_timestamp_rotations_share_a_stable_health_family(self) -> None:
        folder = self.base / "ServiceWorker"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        first = logs / "worker_20260709_055117.log"
        second = logs / "worker_20260709_061245.log"

        self.assertEqual(
            bm.health_candidate_family(first, folder),
            bm.health_candidate_family(second, folder),
        )

    def test_sharded_latest_logs_share_aggregate_progress_family(self) -> None:
        folder = self.base / "DataWorker"
        logs = folder / "launcher_logs"
        logs.mkdir(parents=True)
        btc = logs / "BTC-USD_latest.log"
        eth = logs / "ETH-USD_latest.log"

        btc_family = bm.health_candidate_family(btc, folder)
        eth_family = bm.health_candidate_family(eth, folder)

        self.assertEqual(btc_family, eth_family)
        self.assertIn("<rolling-latest>", btc_family)

    def test_adaptive_threshold_learns_only_bounded_continuous_cadence(self) -> None:
        cfg = self.config_for(self.base)
        cfg["stale_minutes"] = 10
        cfg["adaptive_health_min_samples"] = 3
        cfg["watch_interval_seconds"] = 400
        bot = bm.BotRecord(name="SlowBot", path=str(self.base / "SlowBot"))
        state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}

        assessment = None
        for now in (1000.0, 1900.0, 2800.0, 3700.0):
            candidate = bm.LogCandidate(
                path=str(self.base / "SlowBot" / "logs" / "runtime.log"),
                score=65,
                reliable=True,
                mtime=now,
                reasons=[],
                tier="strong",
                family="logs/runtime.log",
            )
            assessment = bm.assess_health_evidence(
                bot, candidate, cfg, state, now=now, active=True
            )

        self.assertIsNotNone(assessment)
        assert assessment is not None
        self.assertEqual(assessment.sample_count, 3)
        self.assertEqual(assessment.mode, "adaptive")
        self.assertGreater(assessment.effective_threshold_minutes, 40)
        self.assertLessEqual(
            assessment.effective_threshold_minutes,
            cfg["stale_minutes"] * cfg["adaptive_health_max_threshold_factor"],
        )

    def test_monitoring_gap_does_not_become_a_false_cadence_sample(self) -> None:
        cfg = self.config_for(self.base)
        bot = bm.BotRecord(name="GapBot", path=str(self.base / "GapBot"))
        state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}
        first = bm.LogCandidate("runtime.log", 65, True, 1000.0, [], "strong", "logs/runtime.log")
        second = bm.LogCandidate("runtime.log", 65, True, 5000.0, [], "strong", "logs/runtime.log")

        bm.assess_health_evidence(bot, first, cfg, state, now=1000.0, active=True)
        assessment = bm.assess_health_evidence(bot, second, cfg, state, now=5000.0, active=True)

        self.assertEqual(assessment.sample_count, 0)
        self.assertTrue(any("cross-gap" in note for note in assessment.notes))

    def test_same_name_at_new_path_resets_adaptive_history(self) -> None:
        cfg = self.config_for(self.base)
        old_bot = bm.BotRecord(name="MovedBot", path=str(self.base / "Old" / "MovedBot"))
        new_bot = bm.BotRecord(name="MovedBot", path=str(self.base / "New" / "MovedBot"))
        state = {
            "version": bm.HEALTH_STATE_VERSION,
            "bots": {
                "MovedBot": {
                    "bot_identity": bm.health_bot_identity(old_bot),
                    "family": "logs/runtime.log",
                    "last_mtime": 900.0,
                    "last_observed_at": 990.0,
                    "active_last_observation": True,
                    "intervals_seconds": [30.0, 30.0, 30.0, 30.0, 30.0],
                }
            },
        }
        candidate = bm.LogCandidate(
            str(self.base / "New" / "MovedBot" / "logs" / "runtime.log"),
            65,
            True,
            1000.0,
            [],
            "strong",
            "logs/runtime.log",
        )

        assessment = bm.assess_health_evidence(
            new_bot, candidate, cfg, state, now=1000.0, active=True
        )

        self.assertEqual(assessment.sample_count, 0)
        self.assertEqual(assessment.mode, "fixed")
        self.assertTrue(any("path identity changed" in note for note in assessment.notes))
        self.assertEqual(
            state["bots"]["MovedBot"]["bot_identity"], bm.health_bot_identity(new_bot)
        )

    def test_stale_requires_confirmation_unless_hard_overdue(self) -> None:
        cfg = self.config_for(self.base)
        cfg["adaptive_health_enabled"] = False
        cfg["stale_minutes"] = 10
        bot = bm.BotRecord(name="DebouncedBot", path=str(self.base / "DebouncedBot"))
        state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}
        candidate = bm.LogCandidate("runtime.log", 65, True, 300.0, [], "strong", "logs/runtime.log")

        first = bm.assess_health_evidence(bot, candidate, cfg, state, now=1000.0, active=True)
        second = bm.assess_health_evidence(bot, candidate, cfg, state, now=1010.0, active=True)

        self.assertTrue(first.suspect)
        self.assertFalse(first.stale_confirmed)
        self.assertEqual(first.consecutive_suspect, 1)
        self.assertTrue(second.stale_confirmed)
        self.assertEqual(second.consecutive_suspect, 2)

        hard_state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}
        hard_candidate = bm.LogCandidate("runtime.log", 65, True, -300.0, [], "strong", "logs/runtime.log")
        hard = bm.assess_health_evidence(bot, hard_candidate, cfg, hard_state, now=1000.0, active=True)
        self.assertTrue(hard.stale_confirmed)

    def test_stale_confirmation_is_time_gated_across_rapid_observers(self) -> None:
        cfg = self.config_for(self.base)
        cfg["adaptive_health_enabled"] = False
        cfg["stale_minutes"] = 10
        cfg["watch_interval_seconds"] = 10
        bot = bm.BotRecord(name="DebouncedBot", path=str(self.base / "DebouncedBot"))
        state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}
        candidate = bm.LogCandidate("runtime.log", 65, True, 300.0, [], "strong", "logs/runtime.log")

        first = bm.assess_health_evidence(bot, candidate, cfg, state, now=1000.0, active=True)
        rapid_duplicate = bm.assess_health_evidence(
            bot, candidate, cfg, state, now=1001.0, active=True
        )
        next_period = bm.assess_health_evidence(
            bot, candidate, cfg, state, now=1010.0, active=True
        )

        self.assertEqual(first.consecutive_suspect, 1)
        self.assertEqual(rapid_duplicate.consecutive_suspect, 1)
        self.assertFalse(rapid_duplicate.stale_confirmed)
        self.assertTrue(any("rapid duplicate" in note for note in rapid_duplicate.notes))
        self.assertEqual(next_period.consecutive_suspect, 2)
        self.assertTrue(next_period.stale_confirmed)

    def test_future_timestamp_is_clock_skew_not_fresh_progress(self) -> None:
        cfg = self.config_for(self.base)
        bot = bm.BotRecord(name="FutureBot", path=str(self.base / "FutureBot"))
        state = {"version": bm.HEALTH_STATE_VERSION, "bots": {}}
        candidate = bm.LogCandidate("runtime.log", 65, True, 1300.0, [], "strong", "logs/runtime.log")

        assessment = bm.assess_health_evidence(bot, candidate, cfg, state, now=1000.0, active=True)

        self.assertTrue(assessment.clock_skew)
        self.assertIsNone(assessment.age_minutes)
        self.assertFalse(assessment.stale_confirmed)


class StructuredHealthContractTests(IsolatedAppMixin, unittest.TestCase):
    def write_contract(self, folder: Path, **updates: object) -> Path:
        path = folder / "runtime" / "botops_health.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": bm.HEALTH_CONTRACT_SCHEMA,
            "updated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "state": "ready",
            "live": True,
            "ready": True,
            "heartbeat_sequence": 7,
            "progress_sequence": 3,
        }
        payload.update(updates)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def active_status(self, folder: Path, cfg: dict, *, pid: int = 42, created: float = 100.0) -> bm.BotStatus:
        launcher = folder / "START_HERE.bat"
        launcher.write_text("@echo off\n", encoding="utf-8")
        bot = bm.BotRecord(
            name=folder.name,
            path=str(folder),
            launcher=str(launcher),
            launcher_kind="batch",
            launcher_safe=True,
            launcher_approved=True,
        )
        process = bm.ProcessInfo(pid, "cmd.exe", creation_time=created)
        current = bm.ProcessInfo(os.getpid(), "python.exe", creation_time=1.0)
        tracking = bm.TrackingResult([process], [process], [], [], "NONE", [])
        with mock.patch.object(bm, "get_processes", return_value=self.complete_inventory(current, process)), mock.patch.object(
            bm, "track_bot", return_value=tracking
        ):
            return bm.status_for_bots(cfg, {bot.name: bot}, persist_health=False)[0]

    def test_contract_identity_rejects_missing_actual_creation_time(self) -> None:
        candidate = bm.LogCandidate(
            "health.json",
            100,
            True,
            time.time(),
            [],
            evidence_kind="contract",
            contract_pid=42,
            contract_process_started_at_epoch=100.0,
        )
        process = bm.ProcessInfo(42, "worker.exe", creation_time=None)
        self.assertFalse(bm.contract_identity_match(candidate, [process]))

    def test_contract_identity_rejects_pid_without_expected_creation_time(self) -> None:
        candidate = bm.LogCandidate(
            "health.json",
            100,
            True,
            time.time(),
            [],
            evidence_kind="contract",
            contract_pid=42,
            contract_process_started_at_epoch=None,
        )
        process = bm.ProcessInfo(42, "worker.exe", creation_time=100.0)
        self.assertFalse(bm.contract_identity_match(candidate, [process]))

    def test_valid_contract_outranks_nearby_operational_log(self) -> None:
        folder = self.base / "ContractBot"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        log = logs / "runtime.log"
        log.write_text("progress\n", encoding="utf-8")
        contract = self.write_contract(folder, pid=42, process_started_at_epoch=100.0)
        now = time.time()
        os.utime(contract, (now - 120, now - 120))
        os.utime(log, (now, now))
        cfg = self.config_for(self.base)
        bot = bm.BotRecord(name=folder.name, path=str(folder))

        selected = bm.select_health_candidate(bot, cfg, now=now)

        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.evidence_kind, "contract")
        self.assertEqual(selected.tier, "contract")
        self.assertEqual(selected.contract_state, "ready")
        self.assertEqual(selected.contract_heartbeat_sequence, 7)

    def test_contract_states_separate_readiness_liveness_and_degradation(self) -> None:
        folder = self.base / "StateBot"
        folder.mkdir()
        cfg = self.config_for(self.base)
        expected = {
            "ready": "RUNNING/HEALTHY",
            "starting": "STARTING",
            "degraded": "RUNNING/DEGRADED",
            "failed": "RUNNING/UNHEALTHY",
        }
        for state, expected_status in expected.items():
            with self.subTest(state=state):
                live = state != "failed"
                ready = state == "ready"
                self.write_contract(
                    folder,
                    state=state,
                    live=live,
                    ready=ready,
                    pid=42,
                    process_started_at_epoch=100.0,
                )
                bm._LOG_CANDIDATE_CACHE.clear()
                status = self.active_status(folder, cfg)
                self.assertEqual(status.status, expected_status)
                self.assertEqual(status.health_evidence_kind, "contract")
                self.assertTrue(status.health_contract_pid_match)

    def test_live_but_not_ready_is_not_reported_healthy(self) -> None:
        folder = self.base / "WarmBot"
        folder.mkdir()
        cfg = self.config_for(self.base)
        self.write_contract(
            folder,
            state="ready",
            live=True,
            ready=False,
            pid=42,
            process_started_at_epoch=100.0,
        )

        status = self.active_status(folder, cfg)

        self.assertEqual(status.status, "RUNNING/NOT_READY")
        self.assertTrue(any("not ready" in warning for warning in status.warnings))

    def test_pid_mismatch_rejects_contract_and_falls_back_to_log(self) -> None:
        folder = self.base / "BoundBot"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        (logs / "runtime.log").write_text("progress\n", encoding="utf-8")
        cfg = self.config_for(self.base)
        self.write_contract(folder, pid=999, process_started_at_epoch=100.0)

        status = self.active_status(folder, cfg, pid=42, created=100.0)

        self.assertEqual(status.health_evidence_kind, "file")
        self.assertFalse(status.health_contract_pid_match)
        self.assertTrue(any("identity mismatch" in warning for warning in status.warnings))
        self.assertTrue(status.health_contract_errors)

    def test_invalid_contract_is_reported_but_cannot_mask_log_evidence(self) -> None:
        folder = self.base / "InvalidContractBot"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        (logs / "runtime.log").write_text("progress\n", encoding="utf-8")
        contract = folder / "runtime" / "botops_health.json"
        contract.parent.mkdir(parents=True, exist_ok=True)
        contract.write_text('{"schema":"wrong","state":"ready"}', encoding="utf-8")
        cfg = self.config_for(self.base)
        bot = bm.BotRecord(name=folder.name, path=str(folder))

        candidates = bm.find_log_candidates(folder, cfg, force=True)
        selected = bm.select_health_candidate(bot, cfg, candidates=candidates)
        invalid = next(item for item in candidates if item.evidence_kind == "contract")

        self.assertFalse(invalid.reliable)
        self.assertTrue(invalid.contract_errors)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.evidence_kind, "file")

    def test_contract_embedded_future_timestamp_is_time_skew(self) -> None:
        import datetime as datetime_module

        folder = self.base / "FutureContractBot"
        folder.mkdir()
        cfg = self.config_for(self.base)
        future = datetime_module.datetime.now(datetime_module.timezone.utc) + datetime_module.timedelta(hours=1)
        self.write_contract(
            folder,
            updated_at=future.isoformat(),
            pid=42,
            process_started_at_epoch=100.0,
        )

        status = self.active_status(folder, cfg)

        self.assertEqual(status.status, "RUNNING/TIME_SKEW")
        self.assertTrue(status.health_clock_skew)

    def test_oversized_contract_is_bounded_and_rejected(self) -> None:
        folder = self.base / "HugeContractBot"
        folder.mkdir()
        path = folder / "botops_health.json"
        path.write_text("x" * 4096, encoding="utf-8")
        cfg = self.config_for(self.base)
        cfg["health_contract_max_bytes"] = 1024

        candidate = bm.health_contract_candidate(path, folder, cfg)

        self.assertFalse(candidate.reliable)
        self.assertTrue(any("exceeds" in error for error in candidate.contract_errors))


class ProcessIdentityTests(IsolatedAppMixin, unittest.TestCase):
    def test_path_boundary_does_not_match_similar_bot_name(self) -> None:
        path = r"C:\Bots\DataWorker"
        self.assertTrue(bm.path_in_process_text(path, r'python "C:\Bots\DataWorker\main.py"'))
        self.assertFalse(bm.path_in_process_text(path, r'python "C:\Bots\DataWorker2\main.py"'))
        self.assertFalse(bm.path_in_process_text(path, r'python "C:\Bots\DataWorker_Backup\main.py"'))

    def test_observed_tracking_requires_exact_bot_or_launcher_path(self) -> None:
        bot = bm.BotRecord(
            name="DataWorker",
            path=r"C:\Bots\DataWorker",
            launcher=r"C:\Bots\DataWorker\worker_console.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        processes = [
            bm.ProcessInfo(1, "python.exe", command_line=r'python "C:\Bots\OtherBot\main.py"'),
            bm.ProcessInfo(2, "cmd.exe", command_line=r'cmd /k call "C:\Bots\DataWorker\worker_console.bat"'),
            bm.ProcessInfo(3, "python.exe", command_line=r'python "C:\Bots\DataWorker2\main.py"'),
        ]
        observed, roots, confidence, _ = bm.observed_tracking(bot, processes)
        self.assertEqual([item.pid for item in observed], [2])
        self.assertEqual([item.pid for item in roots], [2])
        self.assertEqual(confidence, "HIGH")

    def test_distinctive_relative_launcher_is_monitor_only_match(self) -> None:
        bot = bm.BotRecord(
            name="DataWorker",
            path=r"C:\Bots\DataWorker",
            launcher=r"C:\Bots\DataWorker\worker_console.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        process = bm.ProcessInfo(22, "cmd.exe", command_line=r"cmd.exe /k worker_console.bat")
        observed, roots, confidence, reasons = bm.observed_tracking(bot, [process])
        self.assertEqual([item.pid for item in observed], [22])
        self.assertEqual([item.pid for item in roots], [22])
        self.assertEqual(confidence, "MEDIUM")
        self.assertTrue(any("distinctive launcher" in reason for reason in reasons))

    def test_editor_viewer_path_reference_is_not_counted_as_running_bot(self) -> None:
        bot = bm.BotRecord(
            name="PolicyWorker",
            path=r"C:\Bots\PolicyWorker",
            launcher=r"C:\Bots\PolicyWorker\START_HERE_POLICY_CDE_GOVERNANCE_BOT.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        editor = bm.ProcessInfo(
            31,
            "notepad++.exe",
            command_line=r'notepad++.exe "C:\Bots\PolicyWorker\START_HERE_POLICY_CDE_GOVERNANCE_BOT.bat"',
        )
        runtime = bm.ProcessInfo(
            32,
            "cmd.exe",
            command_line=r'cmd /k call "C:\Bots\PolicyWorker\START_HERE_POLICY_CDE_GOVERNANCE_BOT.bat"',
        )

        observed_editor, roots_editor, confidence_editor, reasons_editor = bm.observed_tracking(bot, [editor])
        observed_runtime, roots_runtime, confidence_runtime, _ = bm.observed_tracking(bot, [runtime])

        self.assertEqual(observed_editor, [])
        self.assertEqual(roots_editor, [])
        self.assertEqual(confidence_editor, "NONE")
        self.assertTrue(any("ignored non-runtime" in reason for reason in reasons_editor))
        self.assertEqual([item.pid for item in observed_runtime], [32])
        self.assertEqual([item.pid for item in roots_runtime], [32])
        self.assertEqual(confidence_runtime, "HIGH")

    def test_observed_launcher_root_expands_to_descendant_tree(self) -> None:
        bot = bm.BotRecord(
            name="DataWorker",
            path=r"C:\Bots\DataWorker",
            launcher=r"C:\Bots\DataWorker\worker_console.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        processes = [
            bm.ProcessInfo(30, "cmd.exe", command_line=r"cmd.exe /k worker_console.bat", creation_time=100),
            bm.ProcessInfo(31, "python.exe", command_line="python main.py", parent_pid=30, creation_time=101),
            bm.ProcessInfo(32, "worker.exe", command_line="worker", parent_pid=31, creation_time=102),
        ]
        observed, roots, confidence, _ = bm.observed_tracking(bot, processes)
        self.assertEqual([item.pid for item in observed], [30, 31, 32])
        self.assertEqual([item.pid for item in roots], [30])
        self.assertEqual(confidence, "MEDIUM")

    def test_generic_relative_launcher_name_is_not_used(self) -> None:
        bot = bm.BotRecord(
            name="GenericBot",
            path=r"C:\Bots\GenericBot",
            launcher=r"C:\Bots\GenericBot\start.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        process = bm.ProcessInfo(23, "cmd.exe", command_line=r"cmd.exe /k start.bat")
        observed, roots, confidence, _ = bm.observed_tracking(bot, [process])
        self.assertEqual(observed, [])
        self.assertEqual(roots, [])
        self.assertEqual(confidence, "NONE")

    def test_descendants_are_limited_to_verified_tree(self) -> None:
        processes = [
            bm.ProcessInfo(10, "cmd.exe", parent_pid=1, creation_time=100),
            bm.ProcessInfo(11, "python.exe", parent_pid=10, creation_time=101),
            bm.ProcessInfo(12, "worker.exe", parent_pid=11, creation_time=102),
            bm.ProcessInfo(20, "python.exe", parent_pid=1, creation_time=90),
        ]
        descendants = bm.collect_descendants([10], processes)
        self.assertEqual([item.pid for item in descendants], [10, 11, 12])

    def test_managed_tracking_rejects_pid_reuse_by_creation_time(self) -> None:
        bot = bm.BotRecord(
            name="ServiceWorker",
            path=r"C:\Bots\ServiceWorker",
            launcher=r"C:\Bots\ServiceWorker\start.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        state = {
            "bots": {
                bot.name: {
                    "launcher_fingerprint": bm.launcher_fingerprint(bot),
                    "started_at_epoch": 100,
                    "roots": [{"pid": 42, "created_at_epoch": 100, "name": "cmd.exe"}],
                }
            }
        }
        reused = [bm.ProcessInfo(42, "cmd.exe", creation_time=500)]
        with mock.patch.object(bm, "read_runtime_state", return_value=state):
            managed, roots, stale = bm.managed_tracking(bot, reused)
        self.assertEqual(managed, [])
        self.assertEqual(roots, [])
        self.assertTrue(stale)

    def test_managed_tracking_rejects_missing_creation_identity(self) -> None:
        bot = bm.BotRecord(
            name="ServiceWorker",
            path=r"C:\Bots\ServiceWorker",
            launcher=r"C:\Bots\ServiceWorker\start.bat",
            launcher_kind="batch",
            launcher_safe=True,
        )
        state = {
            "bots": {
                bot.name: {
                    "launcher_fingerprint": bm.launcher_fingerprint(bot),
                    "started_at_epoch": 100,
                    "roots": [{"pid": 42, "created_at_epoch": 100, "name": "cmd.exe"}],
                }
            }
        }
        no_timestamp = [bm.ProcessInfo(42, "cmd.exe", creation_time=None)]
        with mock.patch.object(bm, "read_runtime_state", return_value=state):
            managed, roots, stale = bm.managed_tracking(bot, no_timestamp)
        self.assertEqual(managed, [])
        self.assertEqual(roots, [])
        self.assertTrue(stale)


class PersistenceAndPrivacyTests(IsolatedAppMixin, unittest.TestCase):
    def test_unchanged_rescan_does_not_rewrite_registry(self) -> None:
        root = self.base / "Bots"
        folder = root / "StableBot"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        cfg = self.config_for(root)

        bm.scan_bots(cfg, save=True)
        registry = bm.registry_path()
        first_stat = registry.stat()
        first_text = registry.read_text(encoding="utf-8")
        time.sleep(0.03)
        bm.scan_bots(cfg, save=True)
        second_stat = registry.stat()
        second_text = registry.read_text(encoding="utf-8")

        self.assertEqual(first_text, second_text)
        self.assertEqual(first_stat.st_mtime_ns, second_stat.st_mtime_ns)

    def test_v1_config_migration_keeps_new_safety_defaults(self) -> None:
        old = {
            "version": 1,
            "bots_root": str(self.base / "Bots"),
            "ignored_dirs": [".git", "custom_cache"],
            "log_dir_names": ["logs", "data"],
            "confirm_start_stop": "false",
            "control_managed_processes_only": False,
        }
        path = bm.config_path()
        path.write_text(json.dumps(old), encoding="utf-8")
        cfg = bm.load_config()

        self.assertEqual(cfg["version"], bm.CONFIG_VERSION)
        self.assertIn("custom_cache", cfg["ignored_dirs"])
        self.assertIn("_BotOpsManager", cfg["ignored_dirs"])
        self.assertIn("data", cfg["log_dir_names"])
        self.assertIn("runtime", cfg["log_dir_names"])
        self.assertFalse(cfg["confirm_start_stop"])
        self.assertTrue(cfg["control_managed_processes_only"])
        self.assertIn("emergency", cfg["blocked_start_terms"])

    def test_root_override_source_is_reported_without_persisting_env_value(self) -> None:
        config_root = self.base / "ConfigBots"
        env_root = self.base / "Env Bots"
        config_root.mkdir()
        env_root.mkdir()
        bm.config_path().write_text(json.dumps({"version": bm.CONFIG_VERSION, "bots_root": str(config_root)}, indent=2), encoding="utf-8")
        with mock.patch.dict(os.environ, {"BOTOPS_BOTS_ROOT": str(env_root)}):
            cfg = bm.load_config()

        self.assertEqual(cfg["bots_root"], str(env_root))
        self.assertEqual(cfg["_bots_root_source"], "BOTOPS_BOTS_ROOT")
        saved = json.loads(bm.config_path().read_text(encoding="utf-8"))
        self.assertEqual(saved["bots_root"], str(config_root))

    def test_redaction_preserves_long_names_and_redacts_contextual_secrets(self) -> None:
        long_name = "PolicyWorker_With_A_Very_Long_But_Harmless_Name"
        text = f"folder={long_name} api_key=abcdefghijklmnopqrstuvwxyz123456 Bearer abcdefghijklmnop"
        redacted = bm.redact(text)
        self.assertIn(long_name, redacted)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("abcdefghijklmnop", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_command_quoting_rejects_cmd_percent_expansion(self) -> None:
        with self.assertRaises(ValueError):
            bm.cmd_quote(r"C:\Bots\%TEMP%\start.bat")
        self.assertEqual(bm.cmd_quote(r"C:\Bots\Safe Bot\start.bat"), r'"C:\Bots\Safe Bot\start.bat"')


    def test_newer_config_schema_is_not_overwritten(self) -> None:
        path = bm.config_path()
        future = {"version": bm.CONFIG_VERSION + 50, "bots_root": str(self.base / "FutureBots"), "future_field": {"keep": True}}
        original = json.dumps(future, indent=2)
        path.write_text(original, encoding="utf-8")

        cfg = bm.load_config()

        self.assertEqual(path.read_text(encoding="utf-8"), original)
        self.assertIn("_schema_guard_warnings", cfg)
        self.assertTrue(any("config schema version" in item for item in cfg["_schema_guard_warnings"]))

    def test_newer_registry_schema_blocks_scan_write(self) -> None:
        root = self.base / "Bots"
        folder = root / "StableBot"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        future = {"version": bm.REGISTRY_VERSION + 10, "updated_at": "future", "bots": {}, "future_field": "preserve"}
        original = json.dumps(future, indent=2)
        bm.registry_path().write_text(original, encoding="utf-8")

        bots = bm.scan_bots(self.config_for(root), save=True)

        self.assertIn("StableBot", bots)
        self.assertEqual(bm.registry_path().read_text(encoding="utf-8"), original)
        self.assertTrue(any("registry schema version" in item for item in bm.state_schema_warnings()))

    def test_control_actions_blocked_when_runtime_schema_is_newer(self) -> None:
        folder = self.base / "LiveBot"
        folder.mkdir()
        launcher = folder / "start_live_bot.bat"
        launcher.write_text("@echo off\n", encoding="utf-8")
        bot = bm.BotRecord(
            name="LiveBot",
            path=str(folder),
            launcher=str(launcher),
            launcher_kind="batch",
            launcher_safe=True,
            launcher_score=100,
        )
        bm.runtime_state_path().write_text(json.dumps({"version": bm.RUNTIME_VERSION + 5, "bots": {}}), encoding="utf-8")
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "get_processes") as processes, mock.patch.object(bm, "confirm_action") as confirm, mock.patch("builtins.print"):
            self.assertFalse(bm.start_bot(bot, cfg))
        processes.assert_not_called()
        confirm.assert_not_called()

    def test_newer_health_schema_does_not_block_control_state(self) -> None:
        future = {"version": bm.HEALTH_STATE_VERSION + 10, "bots": {}, "future_field": "preserve"}
        original = json.dumps(future, indent=2)
        bm.health_state_path().write_text(original, encoding="utf-8")

        self.assertEqual(bm.control_schema_block_reason(), "")
        self.assertTrue(any("health_state schema version" in item for item in bm.state_schema_warnings()))
        self.assertEqual(bm.health_state_path().read_text(encoding="utf-8"), original)

    def test_force_confirmation_cannot_be_disabled_by_global_config(self) -> None:
        bot = bm.BotRecord(name="LiveBot", path=r"C:\Bots\LiveBot")
        cfg = self.config_for(self.base)
        cfg["confirm_start_stop"] = False
        with mock.patch("builtins.input", return_value="wrong-name") as mocked, mock.patch("builtins.print"):
            self.assertFalse(bm.confirm_force_action(bot, "danger", cfg, assume_yes=False))
        mocked.assert_called_once()

    def test_powershell_execution_policy_bypass_is_forced_off_and_not_rendered(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        raw = {
            "version": bm.CONFIG_VERSION - 1,
            "bots_root": str(bots_root),
            "powershell_execution_policy_bypass": True,
        }
        bm.config_path().write_text(json.dumps(raw, indent=2), encoding="utf-8")

        cfg = bm.load_config()

        self.assertFalse(cfg["powershell_execution_policy_bypass"])
        assurance = bm.config_input_assurance(cfg)
        self.assertIn("powershell_execution_policy_bypass", assurance["deprecated_or_forced_off_keys"])
        saved = json.loads(bm.config_path().read_text(encoding="utf-8"))
        self.assertFalse(saved["powershell_execution_policy_bypass"])
        command = bm.build_runner_command_path(
            bots_root / "start.ps1",
            "powershell",
            bots_root,
            {**cfg, "powershell_execution_policy_bypass": True},
        )
        self.assertNotIn("ExecutionPolicy", command)
        self.assertIn("-NoProfile -File", command)

    def test_unknown_config_keys_are_preserved_and_reported(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        raw = {
            "version": bm.CONFIG_VERSION,
            "bots_root": str(bots_root),
            "custom_future_toggle": "keep-me",
        }
        bm.config_path().write_text(json.dumps(raw, indent=2), encoding="utf-8")

        cfg = bm.load_config()

        self.assertEqual(cfg["custom_future_toggle"], "keep-me")
        self.assertIn("custom_future_toggle", bm.config_input_assurance(cfg)["unknown_keys"])
        saved = json.loads(bm.config_path().read_text(encoding="utf-8"))
        self.assertEqual(saved["custom_future_toggle"], "keep-me")

    def test_support_sanitizer_redacts_secret_values_by_key_context(self) -> None:
        cfg = self.config_for(self.base)
        payload = {
            "api_key": "plain-value-that-does-not-match-a-known-token-pattern",
            "nested": {
                "client_secret": "also-plain",
                "account_id": "account-0042",
                "client_id": 987654321,
                "accountId": 123456789,
                "clientSecret": "camel-secret",
                "tenantID": "tenant-camel",
                "portfolioId": "portfolio-camel",
                "secret_or_credential_access": False,
            },
            "label": "Safe Bot Name",
        }

        sanitized = bm.sanitize_for_support(payload, cfg)

        self.assertEqual(sanitized["api_key"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["client_secret"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["account_id"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["client_id"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["accountId"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["clientSecret"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["tenantID"], "***REDACTED_PRESENT***")
        self.assertEqual(sanitized["nested"]["portfolioId"], "***REDACTED_PRESENT***")
        self.assertFalse(sanitized["nested"]["secret_or_credential_access"])
        self.assertEqual(sanitized["label"], "Safe Bot Name")


class StatusTests(IsolatedAppMixin, unittest.TestCase):
    def test_python_launcher_with_only_idle_cmd_wrapper_is_not_healthy(self) -> None:
        folder = self.base / "ServiceWorker"
        folder.mkdir()
        launcher = folder / "main.py"
        launcher.write_text("print('done')\n", encoding="utf-8")
        bot = bm.BotRecord(
            name="ServiceWorker",
            path=str(folder),
            launcher=str(launcher),
            launcher_kind="python",
            launcher_safe=True,
        )
        created = time.time() - 600
        process = bm.ProcessInfo(42, "cmd.exe", creation_time=created)
        state = {
            "bots": {
                bot.name: {
                    "launcher_fingerprint": bm.launcher_fingerprint(bot),
                    "started_at_epoch": created,
                    "roots": [{"pid": 42, "created_at_epoch": created, "name": "cmd.exe"}],
                }
            }
        }
        cfg = self.config_for(self.base)
        current = bm.ProcessInfo(os.getpid(), "python.exe", creation_time=1.0)
        with mock.patch.object(bm, "get_processes", return_value=self.complete_inventory(current, process)), mock.patch.object(
            bm, "read_runtime_state", return_value=state
        ):
            status = bm.status_for_bots(cfg, {bot.name: bot})[0]
        self.assertEqual(status.status, "START_FAILED/WRAPPER_ONLY")
        self.assertTrue(any("runtime child" in warning for warning in status.warnings))

    def test_status_debounces_stale_and_reports_time_skew(self) -> None:
        folder = self.base / "ObservedBot"
        logs = folder / "logs"
        logs.mkdir(parents=True)
        launcher = folder / "start.bat"
        launcher.write_text("@echo off\n", encoding="utf-8")
        heartbeat = logs / "runtime.log"
        heartbeat.write_text("progress\n", encoding="utf-8")
        now = time.time()
        old = now - 11 * 60
        os.utime(heartbeat, (old, old))
        bot = bm.BotRecord(
            name="ObservedBot",
            path=str(folder),
            launcher=str(launcher),
            launcher_kind="batch",
            launcher_safe=True,
        )
        process = bm.ProcessInfo(
            7001,
            "cmd.exe",
            command_line=f'cmd /k call "{launcher}"',
            creation_time=now - 3600,
        )
        cfg = self.config_for(self.base)
        current = bm.ProcessInfo(os.getpid(), "python.exe", creation_time=1.0)

        current_time = [now]
        with mock.patch.object(bm, "get_processes", return_value=self.complete_inventory(current, process)), mock.patch.object(
            bm.time, "time", side_effect=lambda: current_time[0]
        ):
            first = bm.status_for_bots(cfg, {bot.name: bot})[0]
            rapid_duplicate = bm.status_for_bots(cfg, {bot.name: bot})[0]
            current_time[0] += cfg["watch_interval_seconds"]
            second = bm.status_for_bots(cfg, {bot.name: bot})[0]

        self.assertEqual(first.status, "RUNNING/SUSPECT")
        self.assertEqual(rapid_duplicate.status, "RUNNING/SUSPECT")
        self.assertEqual(second.status, "RUNNING/STALE")

        future = time.time() + cfg["health_future_skew_seconds"] + 60
        os.utime(heartbeat, (future, future))
        bm._LOG_CANDIDATE_CACHE.clear()
        with mock.patch.object(bm, "get_processes", return_value=self.complete_inventory(current, process)):
            skewed = bm.status_for_bots(cfg, {bot.name: bot})[0]
        self.assertEqual(skewed.status, "RUNNING/TIME_SKEW")
        self.assertTrue(skewed.health_clock_skew)


class ControlBoundaryTests(IsolatedAppMixin, unittest.TestCase):
    def make_bot(self) -> bm.BotRecord:
        folder = self.base / "LiveBot"
        folder.mkdir(exist_ok=True)
        launcher = folder / "start_live_bot.bat"
        launcher.write_text("@echo off\n", encoding="utf-8")
        return bm.BotRecord(
            name="LiveBot",
            path=str(folder),
            launcher=str(launcher),
            launcher_kind="batch",
            launcher_safe=True,
            launcher_score=100,
        )

    def manager_process(self) -> bm.ProcessInfo:
        return bm.ProcessInfo(os.getpid(), "python.exe", creation_time=50.0)

    def corroborating_process(self) -> bm.ProcessInfo:
        return bm.ProcessInfo(os.getpid() + 1000, "worker.exe", creation_time=51.0)

    def test_windows_inventory_requires_explicit_complete_provenance(self) -> None:
        manager = self.manager_process()
        two_record_partial = bm.ProcessInventory(
            [manager, self.corroborating_process()],
            complete=False,
            source="test-partial",
        )
        with mock.patch.object(bm, "is_windows_host", return_value=True):
            self.assertFalse(bm.process_inventory_reliable([manager]))
            self.assertFalse(bm.process_inventory_reliable(two_record_partial))
            self.assertTrue(bm.process_inventory_reliable(self.complete_inventory(manager, self.corroborating_process())))

    def test_process_cache_preserves_complete_provenance(self) -> None:
        inventory = self.complete_inventory(self.manager_process(), self.corroborating_process())
        inventory.source = "test-cim"
        cfg = self.config_for(self.base)
        cfg["process_cache_seconds"] = 60
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_windows_processes", return_value=inventory
        ) as scan:
            first = bm.get_processes(cfg, force=True)
            second = bm.get_processes(cfg)
        self.assertEqual(scan.call_count, 1)
        self.assertIsInstance(first, bm.ProcessInventory)
        self.assertIsInstance(second, bm.ProcessInventory)
        self.assertTrue(first.complete)
        self.assertTrue(second.complete)
        self.assertEqual(second.source, "test-cim")

    def test_windows_enumerator_marks_only_explicit_complete_envelope_complete(self) -> None:
        raw = {
            "Complete": True,
            "ReportedCount": 2,
            "Items": [
                {
                    "ProcessId": 0,
                    "ParentProcessId": 0,
                    "Name": "System Idle Process",
                    "ExecutablePath": None,
                    "CommandLine": None,
                    "CreationDate": None,
                    "WorkingSetSize": 0,
                },
                {
                    "ProcessId": os.getpid(),
                    "ParentProcessId": 1,
                    "Name": "python.exe",
                    "ExecutablePath": r"C:\\Python\\python.exe",
                    "CommandLine": "python bot_manager.py",
                    "CreationDate": "2026-07-19T11:00:00+00:00",
                    "WorkingSetSize": 1024,
                },
            ],
        }
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(raw), stderr="")
        with mock.patch.object(bm.shutil, "which", return_value=r"C:\\Windows\\powershell.exe"), mock.patch.object(
            bm.subprocess, "run", return_value=completed
        ):
            inventory = bm.get_windows_processes()
        self.assertTrue(inventory.complete)
        self.assertEqual(len(inventory), 1)
        self.assertIn("Win32_Process", inventory.source)

    def test_start_reaudits_persisted_launcher_inside_control_lock(self) -> None:
        bot = self.make_bot()
        blocked = Path(bot.path) / "build_helper.bat"
        blocked.write_text("@echo off\n", encoding="utf-8")
        bot.launcher = str(blocked)
        bot.launcher_safe = True
        bot.launcher_score = 999
        inventory = self.complete_inventory(self.manager_process(), self.corroborating_process())
        cfg = self.config_for(self.base)
        empty_tracking = bm.TrackingResult([], [], [], [], "NONE", [])
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=inventory
        ), mock.patch.object(bm, "track_bot", return_value=empty_tracking), mock.patch.object(
            bm, "confirm_action", return_value=True
        ), mock.patch.object(bm, "popen_new_console") as popen, mock.patch("builtins.print"):
            self.assertFalse(bm.start_bot(bot, cfg))
        popen.assert_not_called()

    def test_start_records_no_ownership_without_exact_launched_pid_identity(self) -> None:
        bot = self.make_bot()
        inventory = self.complete_inventory(self.manager_process(), self.corroborating_process())
        cfg = self.config_for(self.base)
        cfg["start_settle_seconds"] = 0
        empty_tracking = bm.TrackingResult([], [], [], [], "NONE", [])
        launched = SimpleNamespace(pid=4242, poll=mock.Mock(return_value=None))
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", side_effect=[inventory, inventory, inventory, inventory]
        ), mock.patch.object(bm, "track_bot", return_value=empty_tracking), mock.patch.object(
            bm, "confirm_action", return_value=True
        ), mock.patch.object(bm, "popen_new_console", return_value=launched), mock.patch.object(
            bm, "record_runtime_roots"
        ) as record, mock.patch("builtins.print"):
            self.assertTrue(bm.start_bot(bot, cfg))
        record.assert_not_called()

    def test_start_records_ownership_only_when_immediate_and_settled_identity_match(self) -> None:
        bot = self.make_bot()
        baseline = self.complete_inventory(self.manager_process(), self.corroborating_process())
        initial_root = bm.ProcessInfo(4242, "cmd.exe", creation_time=100.0)
        settled_root = bm.ProcessInfo(4242, "cmd.exe", creation_time=100.0)
        immediate = self.complete_inventory(self.manager_process(), self.corroborating_process(), initial_root)
        settled = self.complete_inventory(self.manager_process(), self.corroborating_process(), settled_root)
        cfg = self.config_for(self.base)
        cfg["start_settle_seconds"] = 0
        empty_tracking = bm.TrackingResult([], [], [], [], "NONE", [])
        launched = SimpleNamespace(pid=4242, poll=mock.Mock(return_value=None))
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", side_effect=[baseline, baseline, immediate, settled]
        ), mock.patch.object(bm, "track_bot", return_value=empty_tracking), mock.patch.object(
            bm, "confirm_action", return_value=True
        ), mock.patch.object(bm, "popen_new_console", return_value=launched), mock.patch.object(
            bm, "record_runtime_roots"
        ) as record, mock.patch("builtins.print"):
            self.assertTrue(bm.start_bot(bot, cfg))
        record.assert_called_once_with(bot, [settled_root], mock.ANY)

    def test_start_records_no_ownership_for_same_pid_replacement_after_quick_exit(self) -> None:
        bot = self.make_bot()
        baseline = self.complete_inventory(self.manager_process(), self.corroborating_process())
        initial_root = bm.ProcessInfo(4242, "cmd.exe", creation_time=100.0)
        replacement = bm.ProcessInfo(4242, "unrelated.exe", creation_time=101.0)
        immediate = self.complete_inventory(self.manager_process(), self.corroborating_process(), initial_root)
        settled = self.complete_inventory(self.manager_process(), self.corroborating_process(), replacement)
        cfg = self.config_for(self.base)
        cfg["start_settle_seconds"] = 0
        empty_tracking = bm.TrackingResult([], [], [], [], "NONE", [])
        launched = SimpleNamespace(pid=4242, poll=mock.Mock(side_effect=[None, 0]))
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", side_effect=[baseline, baseline, immediate, settled]
        ), mock.patch.object(bm, "track_bot", return_value=empty_tracking), mock.patch.object(
            bm, "confirm_action", return_value=True
        ), mock.patch.object(bm, "popen_new_console", return_value=launched), mock.patch.object(
            bm, "record_runtime_roots"
        ) as record, mock.patch("builtins.print"):
            self.assertTrue(bm.start_bot(bot, cfg))
        record.assert_not_called()

    def runtime_state(self, bot: bm.BotRecord, process: bm.ProcessInfo) -> dict:
        return {
            "bots": {
                bot.name: {
                    "launcher_fingerprint": bm.launcher_fingerprint(bot),
                    "started_at_epoch": process.creation_time,
                    "roots": [
                        {
                            "pid": process.pid,
                            "created_at_epoch": process.creation_time,
                            "name": process.name,
                        }
                    ],
                }
            }
        }

    def test_forced_termination_is_disabled_without_platform_kill(self) -> None:
        bot = self.make_bot()
        cfg = self.config_for(self.base)
        with mock.patch.object(bm.subprocess, "run") as run, mock.patch("builtins.print"):
            self.assertFalse(bm.force_stop_bot(bot, cfg))
        run.assert_not_called()

    def test_force_stop_refuses_observed_unowned_process(self) -> None:
        bot = self.make_bot()
        cfg = self.config_for(self.base)
        observed = bm.ProcessInfo(
            99,
            "cmd.exe",
            command_line=f'cmd /k call "{bot.launcher}"',
            creation_time=100.0,
        )
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=self.complete_inventory(observed, self.manager_process())
        ), mock.patch.object(bm, "read_runtime_state", return_value={"bots": {}}), mock.patch.object(
            bm.subprocess, "run"
        ) as run, mock.patch("builtins.print"):
            self.assertFalse(bm.force_stop_bot(bot, cfg))
        run.assert_not_called()

    def test_start_blocks_duplicate_observed_instance(self) -> None:
        bot = self.make_bot()
        observed = bm.ProcessInfo(
            100,
            "cmd.exe",
            command_line=f'cmd /k call "{bot.launcher}"',
            creation_time=100.0,
        )
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=self.complete_inventory(observed, self.manager_process())
        ), mock.patch.object(bm, "read_runtime_state", return_value={"bots": {}}), mock.patch.object(
            bm, "confirm_action"
        ) as confirm, mock.patch("builtins.print"):
            self.assertFalse(bm.start_bot(bot, cfg))
        confirm.assert_not_called()

    def test_adoption_blocks_root_without_creation_timestamp(self) -> None:
        bot = self.make_bot()
        root = bm.ProcessInfo(101, "cmd.exe", creation_time=None)
        tracking = bm.TrackingResult([], [], [root], [root], "HIGH", ["exact launcher"])
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=self.complete_inventory(root, self.manager_process())
        ), mock.patch.object(bm, "track_bot", return_value=tracking
        ), mock.patch.object(bm, "confirm_force_action") as confirm, mock.patch("builtins.print"):
            self.assertFalse(bm.adopt_bot(bot, cfg))
        confirm.assert_not_called()


    def test_start_fails_closed_when_process_inventory_is_unavailable(self) -> None:
        bot = self.make_bot()
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=[]
        ), mock.patch.object(bm, "confirm_action") as confirm, mock.patch("builtins.print"):
            self.assertFalse(bm.start_bot(bot, cfg))
        confirm.assert_not_called()

    def test_force_stop_preserves_ownership_when_verification_inventory_fails(self) -> None:
        bot = self.make_bot()
        root = bm.ProcessInfo(4343, "cmd.exe", creation_time=100.0)
        manager = self.manager_process()
        cfg = self.config_for(self.base)
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", side_effect=[[root, manager], []]
        ), mock.patch.object(bm, "read_runtime_state", return_value=self.runtime_state(bot, root)), mock.patch.object(
            bm, "confirm_force_action", return_value=True
        ), mock.patch.object(bm.subprocess, "run", return_value=completed), mock.patch.object(
            bm, "clear_runtime_bot"
        ) as clear, mock.patch.object(bm.time, "sleep"), mock.patch("builtins.print"):
            self.assertFalse(bm.force_stop_bot(bot, cfg))
        clear.assert_not_called()

    def test_unavailable_inventory_does_not_prune_runtime_ownership(self) -> None:
        bot = self.make_bot()
        root = bm.ProcessInfo(4444, "cmd.exe", creation_time=100.0)
        state = self.runtime_state(bot, root)
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "read_runtime_state", return_value=state
        ), mock.patch.object(bm, "write_runtime_state") as write:
            tracking = bm.track_bot(bot, [])
        self.assertEqual(tracking.managed_processes, [])
        write.assert_not_called()

    def test_windows_status_is_unknown_when_inventory_is_unavailable(self) -> None:
        bot = self.make_bot()
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=[]
        ):
            status = bm.status_for_bots(cfg, {bot.name: bot})[0]
        self.assertEqual(status.status, "UNKNOWN/PROCESS_SCAN")
        self.assertEqual(status.control_state, "UNVERIFIED")

    def test_existing_watch_lock_is_preserved_when_inventory_is_unavailable(self) -> None:
        cfg = self.config_for(self.base)
        lock = bm.state_dir() / "watch.pid"
        lock.write_text(json.dumps({"pid": 123, "process_created_at_epoch": 50}), encoding="utf-8")
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=[]
        ):
            self.assertIsNone(bm.acquire_watch_lock(cfg))
        self.assertTrue(lock.exists())


    def test_run_stop_script_blocks_cross_child_scope_at_runtime(self) -> None:
        parent = self.base / "MixedParent"
        child_a = parent / "a"
        child_b = parent / "b"
        child_a.mkdir(parents=True)
        child_b.mkdir(parents=True)
        start = child_a / "start_a_bot.bat"
        stop = child_b / "stop_b_bot.bat"
        start.write_text("@echo off\n", encoding="utf-8")
        stop.write_text("@echo off\n", encoding="utf-8")
        bot = bm.BotRecord(
            name="MixedParent",
            path=str(parent),
            launcher=str(start),
            launcher_kind="batch",
            launcher_safe=True,
            stop_launcher=str(stop),
            stop_launcher_kind="batch",
        )
        cfg = self.config_for(self.base)
        with mock.patch.object(bm, "is_windows_host") as win, mock.patch("builtins.print"):
            self.assertFalse(bm.run_stop_script(bot, cfg))
        win.assert_not_called()

    def test_stop_script_outside_bot_folder_is_blocked(self) -> None:
        bot = self.make_bot()
        outside = self.base / "stop.bat"
        outside.write_text("@echo off\n", encoding="utf-8")
        bot.stop_launcher = str(outside)
        bot.stop_launcher_kind = "batch"
        cfg = self.config_for(self.base)
        with mock.patch("builtins.print"):
            self.assertFalse(bm.run_stop_script(bot, cfg))

    def test_control_action_lock_blocks_parallel_start(self) -> None:
        bot = self.make_bot()
        cfg = self.config_for(self.base)
        cfg["control_action_lock_timeout_seconds"] = 1
        lock = bm.control_action_lock_path()
        lock.write_text(
            json.dumps({
                "pid": 99999,
                "run_id": "other",
                "action": "start",
                "bot_name": bot.name,
                "created_at_epoch": time.time(),
            }),
            encoding="utf-8",
        )
        manager = self.manager_process()
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm, "get_processes", return_value=self.complete_inventory(manager, bm.ProcessInfo(77, "worker.exe", creation_time=51.0))
        ), mock.patch.object(bm, "confirm_action", return_value=True), mock.patch.object(
            bm, "popen_new_console"
        ) as popen, mock.patch("builtins.print"):
            self.assertFalse(bm.start_bot(bot, cfg))
        popen.assert_not_called()
        self.assertTrue(lock.exists())

    def test_control_action_lock_does_not_auto_delete_stale_file(self) -> None:
        cfg = self.config_for(self.base)
        cfg["control_action_lock_timeout_seconds"] = 1
        lock = bm.control_action_lock_path()
        lock.write_text(
            json.dumps({
                "pid": 99999,
                "run_id": "old",
                "action": "start",
                "bot_name": "OldBot",
                "created_at_epoch": time.time() - 999,
            }),
            encoding="utf-8",
        )
        with self.assertRaises(TimeoutError):
            with bm.control_action_lock("NewBot", "start", cfg):
                self.fail("A stale-looking lock must require manual review")
        self.assertTrue(lock.exists())

    def test_lock_cleanup_does_not_remove_successor_owner(self) -> None:
        cfg = self.config_for(self.base)
        control_lock = bm.control_action_lock_path()
        with bm.control_action_lock("LiveBot", "start", cfg):
            successor = {"lock_id": "successor", "pid": 999, "created_at_epoch": time.time()}
            control_lock.write_text(json.dumps(successor), encoding="utf-8")
        self.assertEqual(json.loads(control_lock.read_text(encoding="utf-8"))["lock_id"], "successor")
        control_lock.unlink()

        state_lock = bm.state_dir() / ".write.lock"
        with bm.state_write_lock():
            successor = {"lock_id": "successor", "pid": 999, "created_at": time.time()}
            state_lock.write_text(json.dumps(successor), encoding="utf-8")
        self.assertEqual(json.loads(state_lock.read_text(encoding="utf-8"))["lock_id"], "successor")
        state_lock.unlink()


class LauncherExportHotfixTests(IsolatedAppMixin, unittest.TestCase):
    def test_export_support_does_not_execute_child_export_or_start_scripts(self) -> None:
        bots_root = self.base / "Bots"
        folder = bots_root / "ExporterOnlyBot"
        folder.mkdir(parents=True)
        export_script = folder / "RUN_EXPORT_TO_SUPPORT.bat"
        export_script.write_text("@echo SHOULD_NOT_RUN\n", encoding="utf-8")
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]), mock.patch.object(
            bm, "popen_new_console"
        ) as popen, mock.patch.object(bm.subprocess, "run") as run:
            path = bm.export_support(cfg)

        self.assertTrue(path.exists())
        popen.assert_not_called()
        run.assert_not_called()
        with zipfile.ZipFile(path) as archive:
            audit = json.loads(archive.read("launcher_audit.json"))
        selected = audit["ExporterOnlyBot"]["selected_start"]
        self.assertEqual(selected, "")
        candidates = audit["ExporterOnlyBot"]["start_candidates"]
        export_candidate = next(item for item in candidates if "RUN_EXPORT_TO_SUPPORT" in item["path"])
        self.assertTrue(export_candidate["blocked"])

    def test_export_support_does_not_rewrite_registry_runtime_or_selftest_state_by_default(self) -> None:
        bots_root = self.base / "Bots"
        folder = bots_root / "StableBot"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        registry_original = {"version": bm.REGISTRY_VERSION, "updated_at": "original", "bots": {"OldBot": {"path": "x"}}}
        runtime_original = {"version": bm.RUNTIME_VERSION, "updated_at": "original", "bots": {"OldBot": {"roots": []}}}
        bm.registry_path().write_text(json.dumps(registry_original, indent=2), encoding="utf-8")
        bm.runtime_state_path().write_text(json.dumps(runtime_original, indent=2), encoding="utf-8")
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        self.assertTrue(path.exists())
        self.assertEqual(json.loads(bm.registry_path().read_text(encoding="utf-8")), registry_original)
        self.assertEqual(json.loads(bm.runtime_state_path().read_text(encoding="utf-8")), runtime_original)
        self.assertFalse(bm.health_state_path().exists())
        self.assertFalse(bm.last_selftest_path().exists())

    def test_export_refresh_registry_option_is_reported_but_not_applied(self) -> None:
        bots_root = self.base / "Bots"
        folder = bots_root / "NewBot"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        original = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "original",
            "bots": {"OldBot": {"path": "x"}},
        }
        bm.registry_path().write_text(json.dumps(original), encoding="utf-8")
        cfg = self.config_for(bots_root)
        cfg["export_refresh_registry"] = True

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        self.assertEqual(json.loads(bm.registry_path().read_text(encoding="utf-8")), original)
        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        contract = status["export_contract"]
        self.assertTrue(contract["export_refresh_registry_requested"])
        self.assertFalse(contract["export_refresh_registry_applied"])
        self.assertTrue(contract["read_only_with_respect_to_manager_state"])

    def test_export_selftest_uses_non_mutating_state_capability_check(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            selftest = json.loads(archive.read("selftest.json"))
        state_check = next(
            item for item in selftest["checks"] if item["name"] == "State directory writable"
        )
        self.assertIn("non-mutating report-only check", state_check["detail"])
        self.assertEqual(list(bm.state_dir().glob(".write_probe_*")), [])

    def test_export_leaves_corrupt_state_files_byte_for_byte(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        corrupt = b'{"version": 1, broken'
        targets = [bm.registry_path(), bm.runtime_state_path(), bm.health_state_path()]
        for target in targets:
            target.write_bytes(corrupt)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        self.assertTrue(path.exists())
        for target in targets:
            self.assertEqual(target.read_bytes(), corrupt)
            self.assertEqual(list(target.parent.glob(target.name + ".broken_*")), [])

    def test_cli_export_leaves_corrupt_config_untouched(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        corrupt = b'{"version": 1, broken'
        bm.config_path().write_bytes(corrupt)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            code = bm.run_cli(["--root", str(bots_root), "export"])

        self.assertEqual(code, 0)
        self.assertEqual(bm.config_path().read_bytes(), corrupt)
        self.assertEqual(list(bm.config_path().parent.glob("bot_manager_config.json.broken_*")), [])

    def test_report_only_mode_blocks_direct_manager_state_write(self) -> None:
        with bm.report_only_state_mode():
            with self.assertRaisesRegex(RuntimeError, "Report-only mode"):
                bm.write_json(bm.health_state_path(), {"version": 1})
        self.assertFalse(bm.health_state_path().exists())

    def test_cli_export_does_not_persist_config_migration(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        old_config = {"version": bm.CONFIG_VERSION - 1, "bots_root": str(bots_root), "support_max_files": 20}
        bm.config_path().parent.mkdir(parents=True, exist_ok=True)
        bm.config_path().write_text(json.dumps(old_config, indent=2), encoding="utf-8")

        with mock.patch.object(bm, "get_processes", return_value=[]):
            code = bm.run_cli(["--root", str(bots_root), "export"])

        self.assertEqual(code, 0)
        self.assertEqual(json.loads(bm.config_path().read_text(encoding="utf-8")), old_config)
        self.assertTrue(list(bm.exports_dir().glob("botops_support_*.zip")))

    def test_export_does_not_claim_invalid_manual_heartbeat_as_selected(self) -> None:
        bots_root = self.base / "Bots"
        folder = bots_root / "ManualBot"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        outside = bots_root / "outside.log"
        outside.write_text("not this bot\n", encoding="utf-8")
        registry = {
            "version": bm.REGISTRY_VERSION,
            "updated_at": "",
            "bots": {
                "ManualBot": {
                    "name": "ManualBot",
                    "path": str(folder),
                    "heartbeat_file": str(outside),
                    "heartbeat_manual": True,
                }
            },
        }
        bm.registry_path().write_text(json.dumps(registry), encoding="utf-8")
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            audit = json.loads(archive.read("health_audit.json"))["ManualBot"]
        self.assertTrue(audit["manual"])
        self.assertFalse(audit["manual_selection_valid"])
        self.assertEqual(audit["selected_heartbeat"], "")
        self.assertNotEqual(audit["configured_manual_heartbeat"], "")

    def test_export_support_uses_unique_zip_path_when_called_quickly(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        with mock.patch.object(bm, "get_processes", return_value=[]), mock.patch.object(
            bm, "local_stamp_for_filename", return_value="20260623_120000_000"
        ):
            first = bm.export_support(cfg)
            second = bm.export_support(cfg)
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_python_launcher_uses_bot_venv_first_then_py_launcher_not_manager_venv(self) -> None:
        folder = self.base / "PyBot"
        folder.mkdir()
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm.shutil, "which", side_effect=lambda name: "C:/Windows/py.exe" if name == "py.exe" else None
        ), mock.patch.object(bm.sys, "executable", r"C:\Bots\OtherBot\.venv\Scripts\python.exe"):
            self.assertEqual(bm.find_python_for_bot(folder), "py -3")
        venv_python = folder / ".venv" / "Scripts" / "python.exe"
        venv_python.parent.mkdir(parents=True)
        venv_python.write_text("", encoding="utf-8")
        with mock.patch.object(bm, "is_windows_host", return_value=True), mock.patch.object(
            bm.shutil, "which", return_value="C:/Windows/py.exe"
        ):
            self.assertEqual(bm.find_python_for_bot(folder), bm.cmd_quote(str(venv_python)))


class AtomicSupportExportTests(IsolatedAppMixin, unittest.TestCase):
    def test_export_is_atomic_capped_and_integrity_checked(self) -> None:
        bots_root = self.base / "Bots"
        folder = bots_root / "Stable Bot With Spaces"
        folder.mkdir(parents=True)
        (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        self.assertTrue(path.exists())
        self.assertEqual(list(bm.exports_dir().glob("*.zip.tmp")), [])
        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            names = archive.namelist()
            self.assertLessEqual(len(names), cfg["support_max_files"])
            status = json.loads(archive.read("status.json"))
            self.assertIn("health_state_snapshot", status)
        self.assertTrue(status["export_contract"]["atomic_publish"])
        self.assertTrue(status["export_contract"]["integrity_test_before_publish"])
        self.assertIn("security_boundary", status)
        self.assertEqual(status["resource_guardrails"]["queue_backpressure"], "not applicable; BotOps is a low-volume local manager without producer/consumer queues")

    def test_export_respects_configured_file_cap_without_log_content(self) -> None:
        bots_root = self.base / "Bots"
        for index in range(5):
            folder = bots_root / f"Bot{index}"
            logs = folder / "logs"
            logs.mkdir(parents=True)
            (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
            (logs / "events.log").write_text("heartbeat\n", encoding="utf-8")
        cfg = self.config_for(bots_root)
        cfg["support_max_files"] = 12
        cfg = bm._coerce_config(cfg)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            names = archive.namelist()
            self.assertLessEqual(len(names), 12)
        self.assertFalse(any(name.startswith("bot_log_tails/") for name in names))

    def test_export_status_json_reports_final_entry_plan_and_omissions(self) -> None:
        bots_root = self.base / "Bots"
        for index in range(4):
            folder = bots_root / f"Bot{index}"
            logs = folder / "logs"
            logs.mkdir(parents=True)
            (folder / "start.bat").write_text("@echo off\n", encoding="utf-8")
            (logs / "events.log").write_text("heartbeat\n", encoding="utf-8")
        cfg = self.config_for(bots_root)
        cfg["support_max_files"] = 12
        cfg = bm._coerce_config(cfg)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            status = json.loads(archive.read("status.json"))
        self.assertLessEqual(len(names), 12)
        self.assertEqual(status["export_plan_final"]["entry_count"], len(names))
        self.assertEqual(status["export_plan_final"]["entry_names"], names)
        self.assertGreaterEqual(status["export_plan_final"]["omission_count"], 0)
        self.assertTrue(status["export_plan_final"]["finalized_before_zip_open"])

    def test_export_status_json_contains_environment_snapshot(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        self.assertIn("environment_snapshot", status)
        self.assertIn("python_version", status["environment_snapshot"])

    def test_export_status_json_reports_path_targeting(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        cfg["_bots_root_source"] = "cli --root"

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        self.assertIn("path_targeting", status)
        self.assertEqual(status["path_targeting"]["bots_root_source"], "cli --root")
        self.assertTrue(status["path_targeting"]["exists"])
        self.assertEqual(status["path_targeting"]["scan_write_guard"], "enabled_no_rewrite_when_root_missing")


    def test_export_status_json_contains_omission_control_ledger(self) -> None:
        bots_root = self.base / "Bots"
        service = bots_root / "ServiceWorker"
        utility = bots_root / "UtilityFolder"
        service.mkdir(parents=True)
        utility.mkdir(parents=True)
        (service / "start_service.bat").write_text("@echo off\n", encoding="utf-8")
        (utility / "requirements.txt").write_text("# utility\n", encoding="utf-8")
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        ledger = status["omission_control_ledger"]
        self.assertEqual(ledger["schema"], "omission_control_ledger_v1")
        self.assertEqual(ledger["bots_root"]["scan_write_guard"], "enabled_no_rewrite_when_root_missing")
        self.assertEqual(ledger["discovered_items_count"], 2)
        self.assertTrue(any(item["item"] == "ServiceWorker" for item in ledger["discovered_items"]))
        self.assertIn("support export plan capped and reported", [item["check"] for item in ledger["checklist"]])

    def test_report_only_selftest_missing_config_is_warning_not_failure(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)

        current = bm.ProcessInfo(os.getpid(), "python.exe", creation_time=1.0)
        corroborating = bm.ProcessInfo(os.getpid() + 1, "worker.exe", creation_time=2.0)
        with mock.patch.object(bm, "get_processes", return_value=self.complete_inventory(current, corroborating)):
            result = bm.run_selftest(cfg, {}, persist=False)

        config_check = next(item for item in result["checks"] if item["name"] == "Config JSON")
        self.assertEqual(config_check["status"], "WARN")
        self.assertIn("report-only mode did not create state", config_check["detail"])
        self.assertNotEqual(result["overall"], "FAIL")

    def test_export_preserves_preexisting_stale_temp_archive(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        stale = bm.exports_dir() / "botops_support_interrupted.zip.tmp"
        stale.parent.mkdir(parents=True, exist_ok=True)
        stale.write_text("forensic evidence", encoding="utf-8")
        old_time = time.time() - 72 * 3600
        os.utime(stale, (old_time, old_time))

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        self.assertTrue(path.exists())
        self.assertTrue(stale.exists())
        self.assertEqual(stale.read_text(encoding="utf-8"), "forensic evidence")

    def test_export_contains_security_boundary_operation_trace_and_config_assurance(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        cfg["custom_future_toggle"] = "keep-me"
        cfg["_config_unknown_keys"] = ["custom_future_toggle"]

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        boundary = status["security_boundary"]
        self.assertEqual(boundary["schema"], bm.SECURITY_BOUNDARY_SCHEMA)
        self.assertFalse(boundary["runtime_flags"]["execution_policy_bypass"])
        self.assertEqual(boundary["security_software_inspection"], "not_performed")
        trace = status["operation_trace"]
        self.assertIn(trace["terminal_status"], {"completed", "completed_with_collector_warnings"})
        self.assertEqual(trace["clock_sources"]["duration"], "time.monotonic")
        self.assertGreaterEqual(len(trace["steps"]), 5)
        self.assertIn("custom_future_toggle", status["custom_input_assurance"]["config"]["unknown_keys"])
        self.assertFalse(status["export_contract"]["stale_temp_cleanup_applied"])
        exit_status = status["work_window_exit"]
        self.assertEqual(exit_status["schema"], "support_work_window_exit_v1")
        self.assertEqual(exit_status["actual_tool_timeouts"], [])
        self.assertIn("No tool timeout", exit_status["timeout_statement"])
        self.assertTrue(exit_status["completed_verified"])
        self.assertTrue(exit_status["next_safe_pass"])

    def test_advanced_export_plan_failure_produces_minimal_fallback(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]), mock.patch.object(
            bm, "build_support_export_plan", side_effect=RuntimeError("synthetic collector failure")
        ):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            self.assertIsNone(archive.testzip())
            names = archive.namelist()
            status = json.loads(archive.read("status.json"))
        self.assertLessEqual(len(names), cfg["support_max_files"])
        self.assertTrue(status["fallback_bundle_used"])
        self.assertTrue(status["fallback_bundle"]["used"])
        self.assertEqual(status["operation_trace"]["terminal_status"], "completed_with_fallback")
        self.assertTrue(any(item["name"] == "build_export_plan" for item in status["collector_failures"]))

    def test_work_window_exit_reports_fallback_error_without_false_timeout(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)

        with mock.patch.object(bm, "get_processes", return_value=[]), mock.patch.object(
            bm, "build_support_export_plan", side_effect=RuntimeError("synthetic plan failure")
        ):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            status = json.loads(archive.read("status.json"))
        exit_status = status["work_window_exit"]
        self.assertEqual(exit_status["status"], "completed_with_reported_limits")
        self.assertEqual(exit_status["actual_tool_timeouts"], [])
        self.assertTrue(any(item["name"] == "build_export_plan" for item in exit_status["actual_errors"]))
        self.assertTrue(exit_status["completed_unverified_or_rushed"])
        self.assertIn("No tool timeout", exit_status["timeout_statement"])

    def test_export_redacts_unknown_secret_config_value(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        cfg["api_key"] = 123456789
        cfg["account_id"] = "account-0042"
        cfg["client_id"] = 987654321
        cfg["_config_unknown_keys"] = ["account_id", "api_key", "client_id"]

        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)

        with zipfile.ZipFile(path) as archive:
            exported_cfg = json.loads(archive.read("bot_manager_config.json"))
        self.assertEqual(exported_cfg["api_key"], "***REDACTED_PRESENT***")
        self.assertEqual(exported_cfg["account_id"], "***REDACTED_PRESENT***")
        self.assertEqual(exported_cfg["client_id"], "***REDACTED_PRESENT***")
        exported_text = json.dumps(exported_cfg)
        self.assertNotIn("123456789", exported_text)
        self.assertNotIn("account-0042", exported_text)
        self.assertNotIn("987654321", exported_text)

    def test_support_plan_rejects_unsafe_names_duplicates_and_byte_overflow(self) -> None:
        cfg = self.config_for(self.base / "Bots")
        cfg["support_max_entry_bytes"] = 65_536
        cfg["support_max_total_bytes"] = 65_536
        cfg = bm._coerce_config(cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([(r"C:/outside.txt", b"x")], cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([(r"\\server\share\outside.txt", b"x")], cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([("status.json", b"x"), ("STATUS.JSON", b"y")], cfg)
        for unsafe_name in (
            "CON",
            "con.txt",
            "CONOUT$",
            "COM9",
            "COM\u00b9.txt",
            "LPT9.txt",
            "name.",
            "name ",
            "line\nbreak.txt",
        ):
            with self.subTest(unsafe_name=unsafe_name), self.assertRaises(RuntimeError):
                bm.validate_support_plan([(unsafe_name, b"x")], cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([("\u00e9.txt", b"x"), ("e\u0301.txt", b"y")], cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([("large.bin", b"x" * 65_537)], cfg)
        with self.assertRaises(RuntimeError):
            bm.validate_support_plan([("one.bin", b"x" * 40_000), ("two.bin", b"y" * 40_000)], cfg)

    def test_atomic_writer_never_overwrites_existing_destination(self) -> None:
        cfg = self.config_for(self.base / "Bots")
        destination = bm.exports_dir() / "existing.zip"
        destination.write_bytes(b"preserve")
        with self.assertRaises(RuntimeError):
            bm.write_atomic_support_zip(destination, [("status.json", b"{}\n")], cfg)
        self.assertEqual(destination.read_bytes(), b"preserve")

    def test_atomic_writer_keeps_exclusive_descriptor_through_fsync_and_validation(self) -> None:
        cfg = self.config_for(self.base / "Bots")
        destination = bm.exports_dir() / "descriptor-safe.zip"
        real_zipfile = bm.zipfile.ZipFile
        observed_streams = []

        def inspected_zipfile(file, *args, **kwargs):
            self.assertNotIsInstance(file, (str, Path))
            self.assertTrue(hasattr(file, "fileno"))
            observed_streams.append(file)
            return real_zipfile(file, *args, **kwargs)

        with mock.patch.object(bm.zipfile, "ZipFile", side_effect=inspected_zipfile), mock.patch.object(
            bm.os, "fsync", wraps=bm.os.fsync
        ) as fsync:
            bm.write_atomic_support_zip(destination, [("status.json", b"{}\n")], cfg)

        self.assertTrue(destination.is_file())
        self.assertEqual(len(observed_streams), 2)
        self.assertIs(observed_streams[0], observed_streams[1])
        fsync.assert_called_once()

    def test_export_rejects_reparse_like_managed_exports_directory(self) -> None:
        cfg = self.config_for(self.base / "Bots")
        managed = bm.exports_dir()
        destination = managed / "new.zip"
        original = bm.path_is_reparse_or_symlink

        def looks_linked(path: Path) -> bool:
            return Path(path) == managed or original(Path(path))

        with mock.patch.object(bm, "path_is_reparse_or_symlink", side_effect=looks_linked):
            with self.assertRaises(RuntimeError):
                bm.write_atomic_support_zip(destination, [("status.json", b"{}\n")], cfg)

    def test_report_only_export_creates_no_state_or_log_directory(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        with mock.patch.object(bm, "get_processes", return_value=[]):
            path = bm.export_support(cfg)
        self.assertTrue(path.is_file())
        self.assertFalse((self.manager_root / "state").exists())
        self.assertFalse((self.manager_root / "logs").exists())
        self.assertTrue((self.manager_root / "exports").is_dir())

    def test_report_only_export_does_not_append_preexisting_manager_log(self) -> None:
        bots_root = self.base / "Bots"
        bots_root.mkdir()
        cfg = self.config_for(bots_root)
        log_path = self.manager_root / "logs" / "bot_manager.log"
        log_path.parent.mkdir()
        original = b"existing manager evidence\n"
        log_path.write_bytes(original)
        with mock.patch.object(bm, "get_processes", return_value=[]):
            bm.export_support(cfg)
        self.assertEqual(log_path.read_bytes(), original)

    def test_tail_and_json_reads_are_bounded(self) -> None:
        huge_log = self.base / "huge.log"
        huge_log.write_bytes(b"x" * 200_000)
        self.assertLessEqual(len(bm.tail_file(huge_log, lines=10, max_bytes=4_096)), 4_096)
        huge_json = self.base / "huge.json"
        huge_json.write_bytes(b"{" + b" " * bm.JSON_INPUT_MAX_BYTES + b"}")
        self.assertEqual(bm.load_json(huge_json, {"safe": True}, "oversized", recover=False), {"safe": True})

    def test_shared_bounded_reader_protects_package_and_control_lock_json(self) -> None:
        valid = self.base / "valid.json"
        valid.write_text('{"safe": true}\n', encoding="utf-8")
        self.assertEqual(bm.read_bounded_json(valid, 1024), {"safe": True})

        oversized_package = self.base / "package.json"
        oversized_package.write_bytes(b"{" + b" " * bm.JSON_INPUT_MAX_BYTES + b"}")
        self.assertFalse(bm.package_has_start_script(oversized_package))

        lock_path = bm.control_action_lock_path()
        lock_path.write_bytes(b"{" + b" " * bm.JSON_INPUT_MAX_BYTES + b"}")
        lock = bm.read_control_action_lock()
        self.assertTrue(lock["active"])
        self.assertNotIn("secret", lock)

        with self.assertRaises(ValueError):
            bm.read_bounded_regular_bytes(self.base, 1024)

    def test_run_id_sanitizer_is_filename_safe_and_bounded(self) -> None:
        cleaned = bm._sanitize_run_id(r"..\unsafe/path:$secret " + "x" * 200)
        self.assertRegex(cleaned, r"^[A-Za-z0-9_-]{1,48}$")
        self.assertNotIn("..", cleaned)

    def test_cleanup_stale_temp_exports_keeps_recent_temp_files(self) -> None:
        cfg = self.config_for(self.base / "Bots")
        old_tmp = bm.exports_dir() / "botops_support_old.zip.tmp"
        new_tmp = bm.exports_dir() / "botops_support_new.zip.tmp"
        old_tmp.parent.mkdir(parents=True, exist_ok=True)
        old_tmp.write_text("old", encoding="utf-8")
        new_tmp.write_text("new", encoding="utf-8")
        old_time = time.time() - 48 * 3600
        os.utime(old_tmp, (old_time, old_time))

        bm.cleanup_stale_temp_exports(cfg)

        self.assertFalse(old_tmp.exists())
        self.assertTrue(new_tmp.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
