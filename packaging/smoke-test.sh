#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM

fake_bin="$stage/build"
mkdir -p "$fake_bin"
printf '#!/bin/sh\nexit 0\n' > "$fake_bin/traffic-masqd"
printf '#!/bin/sh\nexit 0\n' > "$fake_bin/traffic-masq"
chmod 0755 "$fake_bin/traffic-masqd" "$fake_bin/traffic-masq"

DESTDIR="$stage/root" BINARY_DIR="$fake_bin" "$project_dir/packaging/install.sh"

test -x "$stage/root/usr/local/sbin/traffic-masqd"
test -x "$stage/root/usr/local/bin/traffic-masq"
test ! -e "$stage/root/etc/traffic-masq/config.toml"

DESTDIR="$stage/opt-root" PREFIX=/opt/traffic-masq BINARY_DIR="$fake_bin" \
    "$project_dir/packaging/install.sh"
test -x "$stage/opt-root/opt/traffic-masq/sbin/traffic-masqd"
test -x "$stage/opt-root/opt/traffic-masq/bin/traffic-masq"

DESTDIR="$stage/root" "$project_dir/packaging/uninstall.sh"
DESTDIR="$stage/opt-root" PREFIX=/opt/traffic-masq "$project_dir/packaging/uninstall.sh"

test ! -e "$stage/root/usr/local/sbin/traffic-masqd"
test ! -e "$stage/root/usr/local/bin/traffic-masq"
printf '%s\n' "packaging staging smoke test passed"
