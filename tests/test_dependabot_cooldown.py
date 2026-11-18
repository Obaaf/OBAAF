"""Every Dependabot updater of this repository waits at least seven days before proposing a version
(flagship slice 2d.4c, the triage of what zizmor and Octoscan reported on this repository).

zizmor's `dependabot-cooldown` audit reported both updaters on 2026-11-11, when neither set a
cooldown. GitHub applies three days when none is set; zizmor asks for seven by default. This holds
the fix in place. It reads `.github/dependabot.yml` only; it does not ask GitHub what it does with it.
"""

import unittest

import yaml

from helpers import ROOT

MINIMUM_DAYS = 7


class DependabotCooldownTests(unittest.TestCase):
    def test_every_updater_waits_at_least_seven_days(self) -> None:
        config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
        updates = config["updates"]
        self.assertTrue(updates, "dependabot.yml has no updaters")
        for update in updates:
            with self.subTest(ecosystem=update.get("package-ecosystem")):
                cooldown = update.get("cooldown")
                self.assertIsInstance(cooldown, dict, "no cooldown: GitHub would wait only its default three days")
                days = cooldown.get("default-days")
                self.assertIsInstance(days, int)
                self.assertNotIsInstance(days, bool)
                self.assertGreaterEqual(days, MINIMUM_DAYS)
                # A per-level setting would override default-days for that level; none may be shorter.
                for key in ("semver-major-days", "semver-minor-days", "semver-patch-days"):
                    if key in cooldown:
                        self.assertGreaterEqual(cooldown[key], MINIMUM_DAYS, key)
                # An exclude list would let the named dependencies skip the wait.
                self.assertNotIn("exclude", cooldown)


if __name__ == "__main__":
    unittest.main()
