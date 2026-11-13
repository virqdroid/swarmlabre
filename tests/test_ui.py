"""The two browser checks (text parity and the page tour), run as tests when headless Firefox and geckodriver are available. They start their own servers and a build of the static
demo from a generated run; they need no model and no Docker. Skipped (not failed) without a browser, because the rest of the suite must pass on a machine that has none."""
import os
import shutil
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "ui"))

BROWSER = shutil.which("geckodriver") and shutil.which("firefox") and not os.environ.get("SWARMLABRE_SKIP_BROWSER")


@unittest.skipUnless(BROWSER, "geckodriver and firefox are not installed (or SWARMLABRE_SKIP_BROWSER is set, as the CI workflow does)")
class BrowserTest(unittest.TestCase):
    def test_text_parity_at_1280_and_500_px_in_live_replay_and_static(self):
        import parity
        self.assertEqual(parity.main([]), 0)

    def test_tour_of_the_page_in_replay_and_static_offline(self):
        import tour
        self.assertEqual(tour.main([]), 0)


@unittest.skipUnless(BROWSER and (Path(__file__).resolve().parent.parent / "site" / "sample" / "report.html").is_file(),
                     "needs a browser and a site/ folder the Copy step of pages.yml has filled (it is built in CI and ignored locally)")
class SiteBrowserTest(unittest.TestCase):
    def test_one_pager_at_1280_and_500_px_with_the_network_blocked(self):
        import importlib.util                # tests/ui/site.py: the stdlib already has a module called `site`, so load ours by path
        spec = importlib.util.spec_from_file_location("site_check", Path(__file__).resolve().parent / "ui" / "site.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.main([]), 0)
