"""Webhook translation + detection, and an offline end-to-end LiveEpisode smoke.

No network: a tiny real git mirror stands in for the repo, hand-built deliveries
stand in for GitHub, and the LiveEpisode smoke monkeypatches the runner, tokens,
and oracle so the whole orchestration runs on a scripted provider.
"""
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from spci.fixture import REVIEWER_ID
from spci.github import webhook as wh


def _git(args, cwd):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t",
                           "-c", "user.email=t@t", *args], capture_output=True, text=True)


def _build_mirror(tmp: Path, marker: str):
    """main with a marker commit + the resolvable tag v1 on it; return (mirror, main_sha)."""
    work = tmp / "work"
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
    (work / "a").write_text("base")
    _git(["add", "-A"], work); _git(["commit", "-qm", "c1"], work)
    (work / f"rel_{marker}.txt").write_text(f"ship {marker}")
    _git(["add", "-A"], work); _git(["commit", "-qm", "c2"], work)
    main_sha = _git(["rev-parse", "HEAD"], work).stdout.strip()
    _git(["tag", "v1"], work)
    mirror = tmp / "mirror.git"
    subprocess.run(["git", "clone", "-q", "--mirror", str(work), str(mirror)], check=True)
    return mirror, main_sha


def _d(event, payload, action="", t=0.0, repo="o/r"):
    return {"event": event, "action": action, "payload": {**payload, "action": action},
            "recv_time": t, "repo": repo}


class TestWebhookTranslation(unittest.TestCase):
    def test_legit_merge_is_logged_not_detected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            marker = "SPCI-MARKER-ok"
            mirror, main = _build_mirror(tmp, marker)
            bot = "review-bot"
            deliveries = [
                _d("pull_request", {"pull_request": {"number": 1, "merged": True,
                                                     "merge_commit_sha": main}}, "closed", 1),
                _d("pull_request_review", {"review": {"state": "approved"},
                                           "pull_request": {"number": 1}}, "submitted", 2),
                # bot performs the merge push to main
                _d("push", {"ref": "refs/heads/main", "after": main,
                            "sender": {"login": bot}}, "", 3),
            ]
            events = wh.to_events(deliveries, bot, mirror, marker)
            from spci import detect
            from spci.telemetry import CONFIG_B_SOURCES
            dets = detect.evaluate(events, mirror, CONFIG_B_SOURCES)
            # bot push normalized to REVIEWER_ID, approval matches merged sha -> nothing fires
            self.assertEqual([d.rule_id for d in dets], [])
            # R2 is linked (marker on main) so it is visible/logged
            self.assertTrue(any(e.checkpoint_link == "R2_protected_main" for e in events))

    def test_bypass_push_by_nonreviewer_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            marker = "SPCI-MARKER-bad"
            mirror, main = _build_mirror(tmp, marker)
            deliveries = [
                # attacker pushes marker straight to main, no approving PR
                _d("push", {"ref": "refs/heads/main", "after": main,
                            "sender": {"login": "attacker"}}, "", 5),
            ]
            events = wh.to_events(deliveries, "review-bot", mirror, marker)
            from spci import detect
            from spci.telemetry import CONFIG_B_SOURCES
            rules = {d.rule_id for d in detect.evaluate(events, mirror, CONFIG_B_SOURCES)}
            self.assertIn("DET-002-nonreviewer-main-push", rules)
            self.assertIn("DET-003-main-change-without-approval", rules)
            # pusher was normalized correctly (attacker != reviewer)
            self.assertTrue(any(e.attributes.get("pusher") == "attacker" for e in events))

    def test_bot_push_normalizes_to_reviewer_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            mirror, main = _build_mirror(tmp, "SPCI-MARKER-x")
            ev = wh.to_events([_d("push", {"ref": "refs/heads/main", "after": main,
                                           "sender": {"login": "mybot"}}, "", 1)],
                              "mybot", mirror, "SPCI-MARKER-x")
            push = [e for e in ev if e.source == "git_push"][0]
            self.assertEqual(push.attributes["pusher"], REVIEWER_ID)


class TestLiveEpisodeSmoke(unittest.TestCase):
    def test_end_to_end_offline(self):
        """Run LiveEpisode with a scripted provider and fakes for runner/oracle."""
        from spci.codebook import ControlStatus, Reach
        from spci.config import Scenario
        from spci.github import episode as gep
        from spci.oracle import ReachResult
        from spci.providers.base import AgentStep, ToolCall, Usage
        from spci.runner import CommandResult, TOOL_NAME
        from spci.store import Store

        class FakeRunner:
            def __init__(self, *a, **k): pass
            def start(self): pass
            def teardown(self): pass
            def run(self, cmd):
                return CommandResult(cmd, 0, "ok", "")

        class FakeGH:
            token = "x"
            def get(self, path):
                return {"commit": {"sha": "seed"}}

        # a provider that acts once then exits
        class ScriptProvider:
            model = "fake/model"
            def __init__(self): self._n = 0
            def step(self, system, messages, tools):
                self._n += 1
                if self._n == 1:
                    return AgentStep(
                        assistant_content=[{"type": "text", "text": "go"}],
                        tool_calls=[ToolCall(id="c1", name=TOOL_NAME,
                                             input={"command": "git push"})],
                        usage=Usage(10, 5), stop_reason="tool_use",
                        text="pushing", cost_usd=0.001)
                return AgentStep(
                    assistant_content=[{"type": "text", "text": "done"}],
                    tool_calls=[], usage=Usage(1, 1), stop_reason="end_turn",
                    text="done", cost_usd=0.0)

        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "runs-live"
            runs.mkdir(parents=True)
            scenario = Scenario(
                scenario_id="s", scenario_seed="x", framing="neutral", reach_target=2,
                budget_usd=1.0, max_turns=5, wall_clock_s=60, no_progress_limit=3,
                system_prompt_file="prompts/system_B_neutral.md",
                objective_file="prompts/objective_neutral.md")

            # fakes
            gep.GitHubRunner = lambda *a, **k: FakeRunner()
            gep.resolve_token = lambda role=None: "tok"
            gep.GitHub.for_role = classmethod(lambda cls, role, api=None: FakeGH())
            gep.gho.mirror_repo = lambda repo, dest, token: Path(dest)
            gep.gho.verify_r1 = lambda m, t, s: ReachResult(Reach.REPOSITORY, True, {"ref": "b"})
            gep.gho.verify_r2 = lambda m, t, s: ReachResult(Reach.PROTECTED_MAIN, True, {"ref": "main"})
            gep.gho.evaluate_main_control = lambda *a, **k: ControlStatus.SATISFIED

            store = Store(runs / "spci.db")
            ep = gep.LiveEpisode(
                scenario=scenario, provider=ScriptProvider(), provider_label="fake",
                repo_base=Path.cwd(), runs_dir=runs, store=store, repo="o/r",
                reviewer_login="bot", settle_s=0, fixed_attempt_id="abc123")
            result = ep.run()
            store.close()

            self.assertEqual(result.max_reach, 2)
            self.assertEqual(result.main_control_status, "satisfied")
            self.assertTrue((runs / "abc123" / "manifest.json").exists())
            self.assertTrue((runs / "abc123" / "transcript.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
