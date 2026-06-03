#!/bin/sh
# GitHub Action entrypoint: maps action inputs to `caminus scan` flags.
#
# GitHub exposes inputs as INPUT_<NAME> env vars, uppercasing the name and
# replacing SPACES with underscores — but NOT hyphens. So input `min-severity`
# becomes `INPUT_MIN-SEVERITY`, which POSIX `${INPUT_MIN-SEVERITY}` cannot read
# (the `-` is the default-value operator). We read every input via `printenv` so
# hyphenated names work, and apply defaults uniformly.
#
# argv is built with `set --` so paths/args with spaces are safe (no eval / no
# sh -c), and caminus's exit code (non-zero when the severity gate trips) is
# preserved so the CI step fails as configured.
set -u

# getin <NAME> <default>: value of INPUT_<NAME>, or default if unset/empty.
getin() {
	v=$(printenv "INPUT_$1" 2>/dev/null) || v=""
	if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "$2"; fi
}

in_path=$(getin PATH ".")
in_platform=$(getin PLATFORM "auto")
in_format=$(getin FORMAT "text")
in_min_severity=$(getin MIN-SEVERITY "info")
in_gate=$(getin GATE "high")
in_fail_incomplete=$(getin FAIL-ON-INCOMPLETE "false")
in_output=$(getin OUTPUT "")
in_args=$(getin ARGS "")

set -- scan "$in_path" \
	--platform "$in_platform" \
	--format "$in_format" \
	--min-severity "$in_min_severity" \
	--gate "$in_gate"

if [ "$in_fail_incomplete" = "true" ]; then
	set -- "$@" --fail-on-incomplete
fi

# Escape hatch: extra raw arguments, intentionally word-split.
if [ -n "$in_args" ]; then
	# shellcheck disable=SC2086
	set -- "$@" $in_args
fi

echo "+ caminus $*" >&2

if [ -n "$in_output" ]; then
	caminus "$@" >"$in_output"
	rc=$?
	echo "caminus: report written to $in_output" >&2
	exit $rc
fi

exec caminus "$@"
