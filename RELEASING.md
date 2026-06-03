# Releasing Caminus

Releases are cut by GoReleaser on a pushed `v*` tag
(`.github/workflows/release.yml`). The default `GITHUB_TOKEN` publishes the
GitHub release with cross-platform archives and `checksums.txt`.

## Cutting a release

```bash
git tag v0.6.0
git push origin v0.6.0
```

GoReleaser builds the dependency-free core binary (`CGO_ENABLED=0`, no
`-tags cloud|yaml`) for linux/darwin/windows × amd64/arm64. The cloud and
structural-YAML engines are intentionally **not** in the prebuilt binaries —
they are opt-in source builds (`go build -tags cloud` / `-tags yaml`).

## Homebrew / Scoop (one-time setup)

Package publishing is gated so binary releases succeed before it is configured.
Until the secret below exists, `SKIP_PKG_PUBLISH` is `true` and the Homebrew/Scoop
steps are skipped (a warning, not a failure).

To enable it:

1. Create two repositories under the `Su1ph3r` org/account:
   - `homebrew-tap` — formula lands in `Formula/caminus.rb`
     (`brew install Su1ph3r/tap/caminus`).
   - `scoop-bucket` — manifest lands in `caminus.json`
     (`scoop bucket add su1ph3r https://github.com/Su1ph3r/scoop-bucket`).
2. Create a fine-grained PAT with **contents: write** on both repos.
3. Add it to the `caminus` repo as the **`TAP_GITHUB_TOKEN`** Actions secret.

The next tagged release then commits the formula/manifest automatically.

**Running GoReleaser locally:** the `skip_upload` templates read `SKIP_PKG_PUBLISH`
from the environment (the CI workflow sets it). When running `goreleaser`
yourself, export it so a local run does not attempt to push to the tap/bucket:

```bash
SKIP_PKG_PUBLISH=true goreleaser release --snapshot --clean   # dry run
SKIP_PKG_PUBLISH=true goreleaser check                        # validate config
```

## GitHub Action

The repository root doubles as a composable Docker action (`action.yml`,
`Dockerfile`, `entrypoint.sh`). Consumers reference `Su1ph3r/caminus@<tag>`; the
action builds the image from source at that ref, so it is always version-
consistent with the tag. See the README "Use in CI" section for inputs.
