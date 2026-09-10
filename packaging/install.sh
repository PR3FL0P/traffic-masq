#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
prefix=${PREFIX:-/usr/local}
binary_dir=${BINARY_DIR:-$project_dir/target/release}

if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this installer as root so it can install files and configure daemon access." >&2
    exit 1
fi

# Host installation is implemented by the daemon so interactive and unattended
# installs share one validated plan. Keep the shell path for compatibility and
# for side-effect-free DESTDIR package staging.
if [ -z "$destdir" ]; then
    exec "$binary_dir/traffic-masqd" install --prefix "$prefix" "$@"
fi

install -D -m 0755 "$binary_dir/traffic-masqd" "$destdir$prefix/sbin/traffic-masqd"
install -D -m 0755 "$binary_dir/traffic-masq" "$destdir$prefix/bin/traffic-masq"
install -D -m 0644 "$project_dir/README.md" \
    "$destdir$prefix/share/doc/traffic-masq/README.md"
if [ -f "$project_dir/examples/config.toml" ]; then
    install -D -m 0644 "$project_dir/examples/config.toml" \
        "$destdir$prefix/share/doc/traffic-masq/config.example.toml"
fi

printf '%s\n' "Staged traffic-masq into $destdir$prefix"
