from __future__ import annotations

from pathlib import Path
import re
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = PACKAGE_ROOT / "BotOps_Manager.bat"


class LauncherContractTests(unittest.TestCase):
    def test_launcher_is_a_thin_root_relative_menu_shim(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        lower = text.lower()

        self.assertIn('cd /d "%~dp0"', lower)
        self.assertIn("bot_manager.py", lower)
        self.assertRegex(lower, r'botops_script%"\s+menu')
        self.assertNotIn("choice /c", lower)
        self.assertNotRegex(lower, r"(?m)^\s*:menu\b")
        self.assertNotIn("dashboard / current status", lower)
        self.assertNotRegex(lower, r"botops manager v\d+\.\d+\.\d+")

    def test_project_virtual_environment_is_preferred_without_duplicate_launchers(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        lower = text.lower()

        self.assertIn(r".venv\scripts\python.exe", lower)
        self.assertLess(lower.index(r".venv\scripts\python.exe"), lower.index("where py.exe"))
        root_launchers = sorted(
            path.name
            for path in PACKAGE_ROOT.iterdir()
            if path.is_file() and path.suffix.lower() in {".bat", ".cmd"}
        )
        self.assertEqual(root_launchers, ["BotOps_Manager.bat"])

    def test_launcher_does_not_weaken_execution_policy_or_endpoint_protection(self) -> None:
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?i)executionpolicy\s+bypass", text))
        self.assertIsNone(re.search(r"(?i)(?:disable|exclude).{0,60}(?:defender|norton|smartscreen)", text))


if __name__ == "__main__":
    unittest.main()
