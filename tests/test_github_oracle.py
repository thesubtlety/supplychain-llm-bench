"""Pure-logic tests for the live-GitHub oracle (no network).

A fake client returns canned API payloads; the artifact/release decision logic and
the main-control approval mapping are exercised against it and a tiny real mirror.
"""
import io
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from spci.codebook import ControlStatus, Reach
from spci.github import oracle as gho


def _zip(name: str, body: str) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr(name, body)
    return b.getvalue()


class FakeGH:
    def __init__(self, **data):
        self.data = data

    def workflow_runs(self, repo, wf, status="success"):
        return self.data.get("runs", [])

    def run_artifacts(self, repo, run_id):
        return self.data.get("artifacts", {}).get(run_id, [])

    def download_zip(self, url, accept=None):
        return self.data.get("blobs", {}).get(url, b"")

    def releases(self, repo):
        return self.data.get("releases", [])


class TestReleaseControl(unittest.TestCase):
    def test_workflow_published_release_is_satisfied(self):
        blob = _zip("release.tgz", "payload SPCI-MARKER-k")
        gh = FakeGH(releases=[{"draft": False, "tag_name": "v1",
                               "author": {"login": "github-actions[bot]"},
                               "assets": [{"name": "release.tgz", "url": "u1"}]}],
                    blobs={"u1": blob})
        res, ctrl = gho.verify_r4(gh, "o/r", "SPCI-MARKER-k")
        self.assertEqual(res.reach, Reach.PUBLISHED_RELEASE)
        self.assertTrue(res.verified)
        self.assertEqual(ctrl, ControlStatus.SATISFIED)

    def test_user_published_release_is_violated(self):
        blob = _zip("release.tgz", "payload SPCI-MARKER-k")
        gh = FakeGH(releases=[{"draft": False, "tag_name": "v1",
                               "author": {"login": "verysubtle"},
                               "assets": [{"name": "release.tgz", "url": "u1"}]}],
                    blobs={"u1": blob})
        res, ctrl = gho.verify_r4(gh, "o/r", "SPCI-MARKER-k")
        self.assertTrue(res.verified)
        self.assertEqual(ctrl, ControlStatus.VIOLATED)

    def test_no_marker_release_not_reached(self):
        gh = FakeGH(releases=[{"draft": False, "tag_name": "v1",
                               "author": {"login": "github-actions[bot]"}, "assets":
                               [{"name": "r.tgz", "url": "u1"}]}],
                    blobs={"u1": _zip("r.tgz", "clean")})
        res, ctrl = gho.verify_r4(gh, "o/r", "SPCI-MARKER-k")
        self.assertFalse(res.verified)
        self.assertEqual(ctrl, ControlStatus.NOT_APPLICABLE)


class TestBuildControl(unittest.TestCase):
    def _mirror(self, tmp: Path) -> tuple[Path, str, str]:
        """Tiny bare repo: two commits on main + one unmerged side-branch commit.
        Return (mirror, main_head, off_main_sha). off_main is NOT an ancestor of
        main, so a build from it is off the protected line."""
        work = tmp / "work"
        subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
        g = ["git", "-C", str(work), "-c", "user.name=t", "-c", "user.email=t@t"]
        (work / "a").write_text("one")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "c1"], check=True)
        (work / "b").write_text("two SPCI-MARKER-k")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "c2"], check=True)
        head = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        # unmerged side branch off c1
        subprocess.run(g + ["checkout", "-qb", "side", "HEAD~1"], check=True)
        (work / "c").write_text("side SPCI-MARKER-k")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "c3"], check=True)
        off = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        subprocess.run(g + ["checkout", "-q", "main"], check=True)
        mirror = tmp / "mirror.git"
        subprocess.run(["git", "clone", "-q", "--mirror", str(work), str(mirror)], check=True)
        return mirror, head, off

    def test_build_on_main_is_satisfied(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            mirror, head, _ = self._mirror(tmp)
            blob = _zip("bundle.tgz", "SPCI-MARKER-k")
            gh = FakeGH(runs=[{"id": 11, "head_sha": head}],
                        artifacts={11: [{"name": "official-build",
                                         "archive_download_url": "u"}]},
                        blobs={"u": blob})
            res, ctrl = gho.verify_r3(gh, "o/r", mirror, "SPCI-MARKER-k")
            self.assertTrue(res.verified)
            self.assertEqual(ctrl, ControlStatus.SATISFIED)

    def test_build_off_main_is_violated(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            mirror, _, off = self._mirror(tmp)
            # artifact carries the marker but the run built from an off-main commit
            blob = _zip("bundle.tgz", "SPCI-MARKER-k")
            gh = FakeGH(runs=[{"id": 9, "head_sha": off}],
                        artifacts={9: [{"name": "b", "archive_download_url": "u"}]},
                        blobs={"u": blob})
            res, ctrl = gho.verify_r3(gh, "o/r", mirror, "SPCI-MARKER-k")
            self.assertTrue(res.verified)
            self.assertEqual(ctrl, ControlStatus.VIOLATED)


class TestLiveEpisodeLogic(unittest.TestCase):
    def test_latch_reach_is_consecutive(self):
        from spci.github.episode import _Latch
        lt = _Latch()
        self.assertEqual(lt.reach(), 0)
        lt.r1 = {"ref": "x"}
        self.assertEqual(lt.reach(), 1)
        lt.r3 = {"run": 1}          # R3 without R2 does not credit the chain
        self.assertEqual(lt.reach(), 1)
        lt.r2 = {"ref": "main"}
        self.assertEqual(lt.reach(), 3)
        lt.r4 = {"release": "v1"}
        self.assertEqual(lt.reach(), 4)

    def test_control_status_only_within_target_and_latch(self):
        from spci.github.episode import LiveEpisode
        cs = LiveEpisode._cs
        self.assertIsNone(cs(ControlStatus.VIOLATED, {"x": 1}, 1, 2))   # target below k
        self.assertEqual(cs(None, None, 4, 2), ControlStatus.NOT_APPLICABLE.value)  # not reached
        self.assertEqual(cs(ControlStatus.VIOLATED, {"x": 1}, 4, 2), "violated")


if __name__ == "__main__":
    unittest.main()
