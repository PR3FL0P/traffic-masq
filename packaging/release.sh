#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary_dir=${BINARY_DIR:-"$project_dir/target/release"}
output_dir=${OUTPUT_DIR:-"$project_dir/release"}
target=${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}
version=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["package"]["version"])' "$project_dir/Cargo.toml")
case "$target" in
    ''|*[!a-zA-Z0-9_-]*) printf '%s\n' 'Invalid target name' >&2; exit 1 ;;
esac
case "$version" in
    ''|*[!a-zA-Z0-9._-]*) printf '%s\n' 'Invalid package version' >&2; exit 1 ;;
esac
if [ "${GITHUB_REF_TYPE:-}" = tag ] && [ "${GITHUB_REF_NAME:-}" != "v$version" ]; then
    printf '%s\n' 'Release tag does not match Cargo.toml version' >&2
    exit 1
fi
name="traffic-masq-$version-$target"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/$name" "$output_dir"
for binary in traffic-masq traffic-masqd; do
    test -x "$binary_dir/$binary"
    cp "$binary_dir/$binary" "$stage/$name/$binary"
done
for doc in README.md LICENSE CHANGELOG.md SECURITY.md CONTRIBUTING.md Cargo.toml; do
    if [ -f "$project_dir/$doc" ]; then
        cp "$project_dir/$doc" "$stage/$name/"
    fi
done
for dir in docs examples packaging; do
    if [ -d "$project_dir/$dir" ]; then
        cp -R "$project_dir/$dir" "$stage/$name/"
    fi
done
tar -czf "$output_dir/$name.tar.gz" -C "$stage" "$name"
(cd "$output_dir" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
printf 'Created %s/%s.tar.gz\n' "$output_dir" "$name"
