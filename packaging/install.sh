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

# Validate the whole staging input before creating any destination files.
if [ "$#" -ne 0 ]; then
    printf '%s\n' "DESTDIR staging does not accept installer arguments; use PREFIX to select the prefix." >&2
    exit 1
fi
for path in "$destdir" "$prefix"; do
    case "$path" in
        /*) ;;
        *) printf '%s\n' "DESTDIR and PREFIX must be absolute paths." >&2; exit 1 ;;
    esac
    case "/$path/" in
        */../*) printf '%s\n' "DESTDIR and PREFIX must not contain '..' components." >&2; exit 1 ;;
    esac
done
for name in traffic-masqd traffic-masq; do
    if [ ! -f "$binary_dir/$name" ] || [ ! -x "$binary_dir/$name" ] || [ -L "$binary_dir/$name" ]; then
        printf '%s\n' "Missing regular executable: $binary_dir/$name. Build both binaries first or set BINARY_DIR." >&2
        exit 1
    fi
done
if [ ! -f "$project_dir/README.md" ]; then
    printf '%s\n' "Missing README.md in release input." >&2
    exit 1
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
