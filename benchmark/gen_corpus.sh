#!/usr/bin/env bash
# Regenerates the Caminus benchmark corpus under benchmark/corpus/ from scratch.
# Each case is a self-contained mini-repo; ground truth lives in manifest.jsonl.
# Idempotent: wipes and rewrites corpus/ on every run.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf corpus
mkdir -p corpus

# w <relpath> writes stdin to corpus/<relpath>, creating parent dirs.
w() { mkdir -p "corpus/$(dirname "$1")"; cat > "corpus/$1"; }

############################ VULN — should be detected ########################

w inj-direct/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks ${{ github.event.pull_request.title }}"
Y

w inj-envrouted/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: echo building $TITLE
Y

w ppe-pwnrequest/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make build
Y

w ppe-indirect-script/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: bash ./ci/build.sh
Y
w ppe-indirect-script/ci/build.sh <<'S'
#!/bin/bash
echo building $TITLE
S

w ppe-reusable/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: ${{ github.event.pull_request.title }}
    secrets: inherit
Y
w ppe-reusable/.github/workflows/reusable.yml <<'Y'
on:
  workflow_call:
    inputs:
      title: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks ${{ inputs.title }}"
Y

w ppe-composite/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        uses: ./.github/actions/greet
        with:
          title: ${{ github.event.pull_request.title }}
Y
w ppe-composite/.github/actions/greet/action.yml <<'Y'
name: greet
inputs:
  title: { required: true }
runs:
  using: composite
  steps:
    - run: echo "Hi ${{ inputs.title }}"
      shell: bash
Y

w run-selfhosted/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request]
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: make build
Y

w perm-writeall/.github/workflows/wf.yml <<'Y'
name: ci
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
Y

w sup-unpinned/.github/workflows/wf.yml <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
Y

w sup-reusable-mutable/.github/workflows/wf.yml <<'Y'
name: ci
on: [push]
jobs:
  build:
    uses: acme/ci/.github/workflows/build.yml@main
    secrets: inherit
Y

w gl-inj/.gitlab-ci.yml <<'Y'
build:
  script:
    - echo "MR from $CI_MERGE_REQUEST_TITLE"
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
Y

w gl-debug/.gitlab-ci.yml <<'Y'
variables:
  CI_DEBUG_TRACE: "true"
build:
  script:
    - make build
Y

############################ SAFE — should NOT be flagged #####################

w safe-inj-envrouted-quoted/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: echo building "$TITLE"
Y

w safe-reusable-static/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  greet:
    uses: ./.github/workflows/reusable.yml
    with:
      title: release-build
Y
w safe-reusable-static/.github/workflows/reusable.yml <<'Y'
on:
  workflow_call:
    inputs:
      title: { type: string }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Thanks ${{ inputs.title }}"
Y

w safe-composite-safeinput/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: greet
        uses: ./.github/actions/greet
        with:
          title: ${{ github.event.pull_request.title }}
          mode: release
Y
w safe-composite-safeinput/.github/actions/greet/action.yml <<'Y'
name: greet
inputs:
  title: { required: true }
  mode: { required: false }
runs:
  using: composite
  steps:
    - run: echo "mode ${{ inputs.mode }}"
      shell: bash
Y

w safe-indirect-quoted/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.pull_request.title }}
    steps:
      - run: bash ./ci/build.sh
Y
w safe-indirect-quoted/ci/build.sh <<'S'
#!/bin/bash
echo building "$TITLE"
S

w safe-sup-pinned/.github/workflows/wf.yml <<'Y'
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: make build
Y

w safe-reusable-pinned/.github/workflows/wf.yml <<'Y'
name: ci
on: [push]
jobs:
  build:
    uses: acme/ci/.github/workflows/build.yml@11bd71901bbe5b1630ceea73d27597364c9af683
    secrets: inherit
Y

############### COVERED (M7) — formerly gaps, now detected ###################

# github-script injection — untrusted ${{ }} in actions/github-script `script:`
# (a JS eval sink). SHA-pinned so CAM-SUP-001 stays silent. Now CAM-INJ-003.
w inj-github-script/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: console.log("${{ github.event.pull_request.title }}")
Y

# nested composite — the caller's action forwards the input to a SECOND composite.
# Caminus follows one hop, so the inner sink is unresolved → CAM-PPE-005 (Info).
w ppe-nested-composite/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/outer
        with:
          title: ${{ github.event.pull_request.title }}
Y
w ppe-nested-composite/.github/actions/outer/action.yml <<'Y'
name: outer
inputs:
  title: { required: true }
runs:
  using: composite
  steps:
    - uses: ./.github/actions/inner
      with:
        forwarded: ${{ inputs.title }}
Y
w ppe-nested-composite/.github/actions/inner/action.yml <<'Y'
name: inner
inputs:
  forwarded: { required: true }
runs:
  using: composite
  steps:
    - run: echo ${{ inputs.forwarded }}
      shell: bash
Y

# local JavaScript action (not composite). Caminus cannot read the JS sink, so
# untrusted input reaching it is UNASSESSED → CAM-PPE-005 (Info).
w ppe-local-js/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/jsgreet
        with:
          title: ${{ github.event.pull_request.title }}
Y
w ppe-local-js/.github/actions/jsgreet/action.yml <<'Y'
name: jsgreet
inputs:
  title: { required: true }
runs:
  using: node20
  main: index.js
Y
w ppe-local-js/.github/actions/jsgreet/index.js <<'J'
const { execSync } = require("child_process");
execSync("echo " + process.env.INPUT_TITLE); // untrusted -> shell
J

####################### KNOWN GAP — vuln Caminus misses ######################

# $GITHUB_ENV cross-step laundering. The write step quotes $TITLE (so the
# inline/indirect rules stay silent), but it writes the untrusted value into
# $GITHUB_ENV; a LATER step then uses that env var unquoted. Caminus does not
# track values that flow through $GITHUB_ENV between steps, so the sink is missed.
w gap-github-env/.github/workflows/wf.yml <<'Y'
name: ci
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "LAUNDERED=$TITLE" >> "$GITHUB_ENV"
      - run: echo building $LAUNDERED
Y

echo "corpus generated: $(find corpus -mindepth 1 -maxdepth 1 -type d | wc -l) cases"
