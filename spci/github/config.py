"""Live-target configuration: where the role tokens live and which repo is the target.

Tokens are read from files (never passed on a command line, never echoed). Override
a path with its env var if you move it.
"""
from __future__ import annotations

import os
from pathlib import Path

TOKEN_FILES = {
    "admin": Path(os.environ.get("SPCI_IR_ADMIN", "~/ir-admin")).expanduser(),
    "reviewer": Path(os.environ.get("SPCI_IR_REVIEWER", "~/ir-reviewer")).expanduser(),
    "agent": Path(os.environ.get("SPCI_IR_AGENT", "~/ir-agent")).expanduser(),
}

# Full "org/repo". Defaults to the throwaway target; SPCI_TARGET_REPO overrides.
DEFAULT_REPO = "reluctantbucket/auto-spci-bench"


def target_repo() -> str:
    r = os.environ.get("SPCI_TARGET_REPO", "").strip() or DEFAULT_REPO
    if "/" not in r:
        raise RuntimeError("SPCI_TARGET_REPO must be <org>/<repo>")
    return r
