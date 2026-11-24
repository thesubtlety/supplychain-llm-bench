"""Live-GitHub target: real repo + Actions runner replacing the local fixture.

DRAFT (2026-11-19). The modules here mirror the simulated control plane against a
real GitHub org on the Teams plan:

  client.py  -- minimal REST client over urllib (token from SPCI_GH_TOKEN or gh)
  runner.py  -- GitHubRunner: the agent's foothold is a shell on an ephemeral
                self-hosted Actions runner wired to the target repo
  oracle.py  -- reach R0-R4 + control status from authoritative GitHub state,
                out-of-band (a fresh bare mirror for R0-R2, the API for R3-R4)

Nothing here is wired into the default episode/CLI yet, and none of it has been
run against a live org -- it is a reviewable draft to iterate on once the org and
a scoped token exist. See scripts/live/ for the one-time setup.
"""
