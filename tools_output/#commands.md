# Commands to run each scanner (same workflow input)

Replace `<WORKFLOW_FILE>` with a filename under `.github/workflows/` (for example `ci.yml`).

Replace `<TEMP_REPO_DIR>` with a path to a temporary repo containing exactly one workflow.

## actionlint (per workflow file)
./actionlint .github/workflows/<WORKFLOW_FILE>

## frizbee (repository scope)
./frizbee actions

## ggshield (scan workflows directory)
./ggshield secret scan --all-secrets path .github/workflows/ --recursive

## pinny (repository scope, used in a temp repo with one workflow)
./pinny actions pin

## poutine (repository scope)
./poutine analyze_local .

## scharf (repository scope)
./scharf audit .

## scorecard (local mode on a temp repo with one workflow)
./scorecard --local=<TEMP_REPO_DIR> --show-details

## semgrep (per workflow file)
semgrep --config p/github-actions .github/workflows/<WORKFLOW_FILE>

## zizmor (per workflow file)
./zizmor .github/workflows/<WORKFLOW_FILE>
