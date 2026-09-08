#!/usr/bin/env sh
# website-version.sh — keep the chaindora.dev website version in lockstep
# with the release tag.
#
#   scripts/website-version.sh set   vX.Y.Z   # stamp website/package.json (+ lockfile)
#   scripts/website-version.sh check vX.Y.Z   # exit 1 if the website disagrees with the tag
#
# The website reads its fallback version from website/package.json at build
# time (see website/src/app/pages/home/home.component.ts), so package.json is
# the single place the version lives. `set` is step 2 of the release flow in
# CLAUDE.md; `check` runs in .github/workflows/release.yml before goreleaser
# so a tag whose website version drifted fails the release instead of
# shipping a stale number.
#
# Requires node + npm (the website build needs them anyway).

set -eu

usage() {
  echo "usage: $0 {set|check} vX.Y.Z" >&2
  exit 2
}

[ $# -eq 2 ] || usage
mode=$1
tag=$2
version=${tag#v}

case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "error: '$tag' is not a vX.Y.Z tag" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
website="$repo_root/website"

read_version() {
  # $1 = JSON file; prints its top-level "version" field.
  node -p "require(process.argv[1]).version" "$1"
}

case "$mode" in
  set)
    # --no-git-tag-version: only rewrite package.json + package-lock.json;
    # the release commit and tag are cut by hand, one commit per tag.
    (cd "$website" && npm version --no-git-tag-version --allow-same-version "$version" >/dev/null)
    echo "website/package.json + package-lock.json set to $version"
    ;;
  check)
    pkg=$(read_version "$website/package.json")
    lock=$(read_version "$website/package-lock.json")
    if [ "$pkg" != "$version" ] || [ "$lock" != "$version" ]; then
      echo "error: website version drifted from tag $tag" >&2
      echo "  website/package.json      = $pkg" >&2
      echo "  website/package-lock.json = $lock" >&2
      echo "fix: scripts/website-version.sh set $tag, commit, then re-tag" >&2
      exit 1
    fi
    echo "website version $pkg matches tag $tag"
    ;;
  *)
    usage
    ;;
esac
