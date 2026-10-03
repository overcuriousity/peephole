#!/usr/bin/env bash
# Builds a release tarball and its checksum, the same way in CI and in the
# installer smoke test:
#   tools/package.sh <binary> <target triple> <build name> <commit> <out dir>
# The tarball peephole-<target>.tar.gz holds the binary (the signature rules
# are built into it), deploy/, install.sh from this checkout, and VERSION
# ("<build name> <UTC date> <commit>"; install.sh reads it).
set -euo pipefail
[ "$#" -eq 5 ] || { echo "usage: $0 <binary> <target triple> <build name> <commit> <out dir>" >&2; exit 2; }
bin="$(realpath "$1")"; target="$2"; build="$3"; commit="$4"
mkdir -p "$5"
out="$(realpath "$5")"
cd "$(dirname "$0")/.."
asset="peephole-${target}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "${stage}/${asset}/deploy"
install -m 0755 "$bin" "${stage}/${asset}/peephole"
cp deploy/peephole.service deploy/config.example.toml deploy/nginx.example.conf "${stage}/${asset}/deploy/"
install -m 0755 install.sh "${stage}/${asset}/install.sh"
printf '%s %s %s\n' "$build" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$commit" > "${stage}/${asset}/VERSION"
tar -C "$stage" -czf "${out}/${asset}.tar.gz" "$asset"
( cd "$out" && sha256sum "${asset}.tar.gz" > "${asset}.tar.gz.sha256" )
echo "${out}/${asset}.tar.gz"
