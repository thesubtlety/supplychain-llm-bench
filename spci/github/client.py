"""Minimal GitHub REST client over urllib -- zero-dep, same style as the providers.

Read-only for the oracle; the setup scripts' review bot also writes. The token is
resolved fail-closed: SPCI_GH_TOKEN if set, else `gh auth token`, else an error.
Keep the throwaway-org token in SPCI_GH_TOKEN (a fine-grained PAT scoped to that
org only) so the agent run never borrows your real account credential.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
_RETRY = (403, 429)


class GitHubError(RuntimeError):
    pass


def read_token_file(path) -> str:
    """Read a PAT from a file; fail closed (never return or log a partial/empty value)."""
    p = Path(path).expanduser()
    try:
        data = p.read_text().strip()
    except OSError as e:
        raise GitHubError(f"cannot read token file {p}: {e}")
    if not data:
        raise GitHubError(f"token file {p} is empty")
    return data


def resolve_token(role: str | None = None) -> str:
    """A role ('admin'|'reviewer'|'agent') reads its token file; otherwise fall back
    to SPCI_GH_TOKEN then `gh auth token`."""
    if role:
        from .config import TOKEN_FILES
        if role not in TOKEN_FILES:
            raise GitHubError(f"unknown token role {role!r}")
        return read_token_file(TOKEN_FILES[role])
    tok = os.environ.get("SPCI_GH_TOKEN", "").strip()
    if tok:
        return tok
    try:
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    raise GitHubError("no GitHub token: set a role, SPCI_GH_TOKEN, or run `gh auth login`")


class GitHub:
    def __init__(self, token: str | None = None, api: str = API, role: str | None = None):
        self.token = token or resolve_token(role)
        self.api = api

    @classmethod
    def for_role(cls, role: str, api: str = API) -> "GitHub":
        return cls(role=role, api=api)

    def _req(self, method: str, path: str, body=None, raw: bool = False):
        url = path if path.startswith("http") else self.api + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data:
            req.add_header("Content-Type", "application/json")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    payload = resp.read()
                    if raw:
                        return payload
                    return json.loads(payload) if payload else None
            except urllib.error.HTTPError as e:
                if e.code in _RETRY or e.code >= 500:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError(f"{method} {url} -> {e.code}: {e.read()[:200]!r}")
            except urllib.error.URLError as e:
                if attempt == 2:
                    raise GitHubError(f"{method} {url}: {e}")
                time.sleep(2 ** attempt)
        raise GitHubError(f"{method} {url}: retries exhausted")

    def get(self, path: str, raw: bool = False):
        return self._req("GET", path, raw=raw)

    def post(self, path: str, body):
        return self._req("POST", path, body)

    def put(self, path: str, body):
        return self._req("PUT", path, body)

    def delete(self, path: str):
        return self._req("DELETE", path)

    def paginate(self, path: str) -> list:
        """Walk a list endpoint to the end (per_page=100)."""
        items: list = []
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            batch = self.get(f"{path}{sep}per_page=100&page={page}")
            if not batch:
                break
            items.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return items

    # --- endpoints the live harness needs ---------------------------------

    def runner_registration_token(self, repo: str) -> str:
        return self.post(f"/repos/{repo}/actions/runners/registration-token", {})["token"]

    def remove_runner(self, repo: str, runner_id: int) -> None:
        self.delete(f"/repos/{repo}/actions/runners/{runner_id}")

    def list_runners(self, repo: str) -> list:
        return (self.get(f"/repos/{repo}/actions/runners") or {}).get("runners", [])

    def workflow_runs(self, repo: str, workflow: str, status: str = "success") -> list:
        r = self.get(f"/repos/{repo}/actions/workflows/{workflow}/runs?status={status}")
        return (r or {}).get("workflow_runs", [])

    def run_artifacts(self, repo: str, run_id: int) -> list:
        r = self.get(f"/repos/{repo}/actions/runs/{run_id}/artifacts")
        return (r or {}).get("artifacts", [])

    def download_zip(self, url: str, accept: str = "application/vnd.github+json") -> bytes:
        """Download a binary (artifact zip or release asset). Auth goes only to the
        api host via add_unredirected_header, so the 302 to the signed blob store is
        fetched without a second auth mechanism (which GitHub's CDN rejects)."""
        req = urllib.request.Request(url)
        req.add_unredirected_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                if e.code in _RETRY or e.code >= 500:
                    time.sleep(2 ** attempt)
                    continue
                raise GitHubError(f"GET {url} -> {e.code}")
            except urllib.error.URLError:
                if attempt == 2:
                    raise
                time.sleep(2 ** attempt)
        raise GitHubError(f"GET {url}: retries exhausted")

    def releases(self, repo: str) -> list:
        return self.paginate(f"/repos/{repo}/releases")

    def commit_pulls(self, repo: str, sha: str) -> list:
        """PRs associated with a commit (the merge that carried it onto main)."""
        return self.get(f"/repos/{repo}/commits/{sha}/pulls") or []

    def pull_reviews(self, repo: str, number: int) -> list:
        return self.paginate(f"/repos/{repo}/pulls/{number}/reviews")

    def attestations(self, repo: str, digest_sha256: str) -> list:
        """Build-provenance attestations for an artifact digest (sha256:...)."""
        r = self.get(f"/repos/{repo}/attestations/sha256:{digest_sha256}")
        return (r or {}).get("attestations", [])
