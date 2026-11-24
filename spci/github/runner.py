"""GitHubRunner: the agent's foothold is a shell on a real, ephemeral self-hosted
Actions runner wired to the target repo.

Contrast with DockerRunner (fixture): that starts a fresh network-less container
per command with state in a bind mount. The live runner is ONE long-lived
container per attempt -- the agent's shell and the CI executor are the same box,
so build-output tampering (an R3 attack) is a genuine surface. The container MUST
reach github.com, so the network is not disabled; production must place it behind
an egress allowlist to github.com + the Actions service only.

Lifecycle:
  start()    -- mint a runner registration token, launch the container (it
                configures + runs the Actions runner and opens a shell), hand the
                agent a scoped GITHUB_TOKEN and a checkout at /srv/ci/workspace.
  run(cmd)   -- exec the command in the container as the unprivileged runner user.
  teardown() -- deregister the runner and destroy the container.

Exposes .run(command) -> CommandResult, so the episode drives it exactly like the
fixture runner. Requires the `spci-gh-runner` image (scripts/live/Dockerfile.gh-runner)
and passwordless `sudo docker`. DRAFT: not yet run against a live org.
"""
from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass, field

from ..runner import CommandResult
from .client import GitHub, resolve_token
from .config import target_repo

IMAGE = "spci-gh-runner:0.1"
WORKDIR = "/srv/ci/workspace"
RUNNER_USER = "runner"


@dataclass
class GitHubRunner:
    repo: str                       # "org/repo"
    agent_token: str                # scoped GITHUB_TOKEN the compromised runner holds
    gh: GitHub                      # control-plane client (admin token; mints runner tokens)
    image: str = IMAGE
    timeout_s: float = 60.0
    labels: str = "spci"
    # No egress firewall by decision: the run is supervised, single-attempt, and
    # killed on teardown or by the lifetime cap below. Bridge = plain outbound.
    network: str = "bridge"
    # Hard self-destruct: the container exits on its own after this many seconds
    # even if nothing calls teardown(), so a forgotten runner can't linger online.
    max_lifetime_s: int = 1800
    _name: str = field(default="", init=False)
    _runner_id: int | None = field(default=None, init=False)

    @classmethod
    def from_config(cls, repo: str | None = None, **kw) -> "GitHubRunner":
        """Build with the admin token as the control plane and ~/ir-agent as the
        agent's scoped credential."""
        return cls(
            repo=repo or target_repo(),
            agent_token=resolve_token("agent"),
            gh=GitHub.for_role("admin"),
            **kw,
        )

    def start(self) -> None:
        self._name = f"spci-run-{uuid.uuid4().hex[:10]}"
        reg = self.gh.runner_registration_token(self.repo)
        argv = [
            "sudo", "-n", "docker", "run", "-d", "--rm",
            "--name", self._name,
            "--network", self.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "2g", "--pids-limit", "512", "--cpus", "2",
            "-e", f"SPCI_REPO={self.repo}",
            "-e", f"RUNNER_TOKEN={reg}",
            "-e", f"RUNNER_LABELS={self.labels}",
            "-e", f"RUNNER_NAME={self._name}",
            "-e", f"RUNNER_MAX_LIFETIME={int(self.max_lifetime_s)}",
            # the credential the agent's foothold starts with (scoped, non-admin).
            # Set on both names so git (URL) and gh (GH_TOKEN) work in exec sessions.
            "-e", f"GITHUB_TOKEN={self.agent_token}",
            "-e", f"GH_TOKEN={self.agent_token}",
            self.image,
        ]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"runner start failed: {r.stderr[:300]}")
        self._wait_registered()

    def _wait_registered(self, tries: int = 30) -> None:
        for _ in range(tries):
            for rn in self.gh.list_runners(self.repo):
                if rn.get("name") == self._name:
                    self._runner_id = rn["id"]
                    return
            subprocess.run(["sleep", "2"])
        # Not fatal for the agent's shell, but CI jobs will queue with no runner.

    def run(self, command: str) -> CommandResult:
        if not self._name:
            raise RuntimeError("runner not started")
        inner = str(int(self.timeout_s))
        argv = [
            "sudo", "-n", "docker", "exec",
            "-u", RUNNER_USER, "-w", WORKDIR, self._name,
            "timeout", inner, "bash", "-lc", command,
        ]
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               timeout=self.timeout_s + 20)
            return CommandResult(command, r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired:
            return CommandResult(command, 124, "", f"exec timeout after {self.timeout_s}s")

    def teardown(self) -> None:
        if self._runner_id is not None:
            try:
                self.gh.remove_runner(self.repo, self._runner_id)
            except Exception:
                pass
        if self._name:
            subprocess.run(["sudo", "-n", "docker", "rm", "-f", self._name],
                           capture_output=True, text=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.teardown()
        return False
