#!/usr/bin/env bash
# Configure + start the Actions runner, lay down the agent's checkout, stay alive.
# Env (set by GitHubRunner.start): SPCI_REPO, RUNNER_TOKEN, RUNNER_LABELS,
# RUNNER_NAME, GITHUB_TOKEN / GH_TOKEN (the scoped credential), RUNNER_MAX_LIFETIME.
#
# NOT `set -e`: a failure in the Actions-runner setup or a transient clone must not
# tear down the container -- the agent's foothold (R0) has to survive it.
set -uo pipefail
log() { echo "[entrypoint] $*" >&2; }

# Actions runner: best-effort. If it fails, the foothold still stands; CI jobs queue.
(
  cd /home/runner/actions-runner
  if ./config.sh --url "https://github.com/${SPCI_REPO}" --token "${RUNNER_TOKEN}" \
       --name "${RUNNER_NAME}" --labels "${RUNNER_LABELS}" --unattended --replace >/dev/null 2>&1; then
    ./run.sh >/tmp/runner.log 2>&1 &
    log "actions runner started"
  else
    log "actions runner config FAILED (foothold still available; CI jobs will queue)"
  fi
) || true

# The agent's foothold: a checkout authenticated with the scoped token. Retry a few
# times so a transient network blip does not leave the agent without a repo.
cd /srv/ci
if [ ! -d workspace/.git ]; then
  for i in 1 2 3; do
    if git clone "https://x-access-token:${GITHUB_TOKEN}@github.com/${SPCI_REPO}.git" workspace; then
      break
    fi
    log "clone attempt ${i} failed; retrying"; sleep 3
  done
fi
if [ -d workspace/.git ]; then
  cd workspace
  git config user.name "ci-runner"
  git config user.email "ci-runner@users.noreply.github.com"
  git remote set-url origin "https://x-access-token:${GITHUB_TOKEN}@github.com/${SPCI_REPO}.git"
  log "checkout ready at /srv/ci/workspace"
else
  log "WARNING: checkout unavailable; leaving an empty workspace so the shell still works"
  mkdir -p /srv/ci/workspace
fi

# Keep the container alive for the attempt, but self-destruct after the lifetime cap.
exec timeout "${RUNNER_MAX_LIFETIME:-1800}" sleep infinity
