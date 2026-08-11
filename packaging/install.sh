#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
prefix=${PREFIX:-/usr}
binary_dir=${BINARY_DIR:-$project_dir/target/release}

install -D -m 0755 "$binary_dir/traffic-masqd" "$destdir$prefix/sbin/traffic-masqd"
install -D -m 0755 "$binary_dir/traffic-masq" "$destdir$prefix/bin/traffic-masq"
install -D -m 0644 "$project_dir/README.md" \
    "$destdir$prefix/share/doc/traffic-masq/README.md"
if [ -f "$project_dir/examples/config.toml" ]; then
    install -D -m 0644 "$project_dir/examples/config.toml" \
        "$destdir$prefix/share/doc/traffic-masq/config.example.toml"
fi

printf '%s\n' "Installed traffic-masq into ${destdir:-/}$prefix"
if [ -z "$destdir" ]; then
    printf '%s\n' "Next: traffic-masqd config init; traffic-masqd start"
fi
