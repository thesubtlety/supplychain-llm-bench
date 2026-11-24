"""Official release + attestation (R4; design.md checkpoint 4).

Models the release workflow that fires on a release tag (`v*`). When a new tag
appears, the releaser resolves its commit, (re)builds it through the official
builder, publishes the build artifact as a release, and writes an attestation
linking release -> build -> source. It is a trusted harness actor; the agent can
push a tag but cannot forge the release record.

Trusted provenance is the releaser's in-process records, not the on-disk log.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .builder import Builder
from .fixture import Fixture
from .telemetry import emit

RELEASER_ID = "official-releaser"
RELEASE_TAG_PREFIX = "refs/tags/v"


def _git(args, cwd) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, errors="replace")


@dataclass
class ReleaseRecord:
    release_id: str
    tag: str
    source_sha: str
    build_id: str
    build_digest: str
    artifact_digest: str
    releaser: str
    time: float


class Releaser:
    def __init__(self, fixture: Fixture, builder: Builder):
        self.fx = fixture
        self.builder = builder
        self.clone = builder.clone
        self.releases_dir = fixture.control_dir / "releases"
        self.releases_dir.mkdir(exist_ok=True)
        self.log = fixture.control_dir / "releases.jsonl"
        self.records: list[ReleaseRecord] = []
        self._released_tags: set[str] = set()

    def _release_tags(self) -> list[str]:
        self.builder._ensure_clone()
        out = _git(["for-each-ref", "--format=%(refname)", "refs/tags/"], self.clone).stdout
        return [t for t in out.splitlines() if t.startswith(RELEASE_TAG_PREFIX)]

    def release_new_tags(self) -> list[ReleaseRecord]:
        """Publish a release for each new `v*` tag on origin."""
        out: list[ReleaseRecord] = []
        for tag in self._release_tags():
            if tag in self._released_tags:
                continue
            self._released_tags.add(tag)
            source_sha = _git(["rev-parse", f"{tag}^{{commit}}"], self.clone).stdout.strip()
            if not source_sha:
                continue
            build = self.builder.build_commit(source_sha)
            release_id = f"{tag.rsplit('/', 1)[-1]}-{build.output_digest[:8]}"
            out_dir = self.releases_dir / release_id
            out_dir.mkdir(exist_ok=True)
            artifact = out_dir / "artifact.txt"
            shutil.copyfile(build.bundle_path, artifact)
            artifact_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            rec = ReleaseRecord(release_id, tag, source_sha, build.build_id,
                                build.output_digest, artifact_digest, RELEASER_ID, time.time())
            (out_dir / "attestation.json").write_text(json.dumps(rec.__dict__, indent=2))
            with open(self.log, "a") as fh:
                fh.write(json.dumps(rec.__dict__) + "\n")
            emit(self.fx.telemetry_log, "release", "release_published",
                 release_id=release_id, tag=tag, source_sha=source_sha,
                 build_id=build.build_id, artifact_digest=artifact_digest, actor=RELEASER_ID)
            self.records.append(rec)
            out.append(rec)
        return out

    def issued_releases(self) -> list[dict]:
        """Trusted, in-process release records (not the forgeable on-disk log)."""
        return [r.__dict__ for r in self.records]
