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
   - `homebrew-tap` — **cask** lands in `Casks/caminus.rb`
     (`brew install --cask Su1ph3r/tap/caminus`). GoReleaser deprecated formula
     generation, so Caminus ships a binary **cask**, not a formula.
   - `scoop-bucket` — manifest lands in `caminus.json`
     (`scoop bucket add su1ph3r https://github.com/Su1ph3r/scoop-bucket`).
2. Create a fine-grained PAT with **contents: write** on both repos.
3. Add it to the `caminus` repo as the **`TAP_GITHUB_TOKEN`** Actions secret.

The next tagged release then commits the cask/manifest automatically.

### macOS Gatekeeper (unsigned binary)

The darwin binaries are **not** code-signed or notarized (that needs a paid
Apple Developer account). The cask therefore carries a `postflight` hook that
strips the `com.apple.quarantine` xattr so Gatekeeper does not block the binary
on first run — the GoReleaser-recommended pattern for unsigned binary casks. The
trust decision is made when the user taps `Su1ph3r/homebrew-tap`; integrity is
still anchored by the `checksums.txt` the cask's sha256 values are pinned to.

**Upgrade path (preferred once an Apple Developer account exists):** sign +
notarize the darwin builds in the release pipeline (GoReleaser `notarize:` /
`rcodesign`, or `gon`/`quill`) and **remove the quarantine-strip hook** — once
notarized, Gatekeeper validates automatically and the strip is unnecessary.

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

### Moving the `v0` major tag (do after each release)

Consumers pin to a major tag (`Su1ph3r/caminus@v0`, the README example). After a
release succeeds, move `v0` to the new release commit so `@v0` users get it:

```bash
git tag -f v0 v0.7.0      # point v0 at the just-released tag
git push -f origin v0
```

(Once a `v1.0.0` exists, maintain `v1` the same way.)

### Publishing to the GitHub Actions Marketplace (one-time UI step)

Marketplace publishing cannot be done from the CLI — it is a checkbox in the
release UI and a one-time agreement:

1. The repo must be public and have `action.yml` at the root with a unique `name`
   and a valid `branding` (icon from the Feather set + color). Caminus uses
   `icon: shield`, `color: orange`, name `Caminus CI/CD Scan` — already set.
2. Go to the release (Releases → the `v0.7.0` release → Edit), check
   **"Publish this Action to the GitHub Marketplace"**, accept the GitHub
   Marketplace Developer Agreement (first time only), pick categories
   (Security / Continuous integration), and Update the release.
3. Subsequent releases offer the same checkbox; the agreement is already accepted.
