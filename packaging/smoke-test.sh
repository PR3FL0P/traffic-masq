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

# Invalid staging requests must fail before installing either binary.
expect_staging_failure() {
    if "$@" >"$stage/failure.log" 2>&1; then
        printf '%s\n' "Invalid staging request unexpectedly succeeded" >&2
        exit 1
    fi
    test ! -e "$stage/rejected"
}
expect_staging_failure env DESTDIR="$stage/rejected" PREFIX=relative BINARY_DIR="$fake_bin" \
    "$project_dir/packaging/install.sh"
expect_staging_failure env DESTDIR="$stage/rejected" PREFIX=/opt/../usr BINARY_DIR="$fake_bin" \
    "$project_dir/packaging/install.sh"
expect_staging_failure env DESTDIR="$stage/rejected" BINARY_DIR="$fake_bin" \
    "$project_dir/packaging/install.sh" --dry-run
chmod 0644 "$fake_bin/traffic-masq"
expect_staging_failure env DESTDIR="$stage/rejected" BINARY_DIR="$fake_bin" \
    "$project_dir/packaging/install.sh"
chmod 0755 "$fake_bin/traffic-masq"

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
BINARY_DIR="$fake_bin" OUTPUT_DIR="$stage/releases" TARGET=x86_64-unknown-linux-gnu \
    "$project_dir/packaging/release.sh"
archive=$(find "$stage/releases" -name '*.tar.gz' -type f)
test -n "$archive"
(cd "$stage/releases" && sha256sum -c ./*.sha256)
mkdir "$stage/unpacked"
tar -xzf "$archive" -C "$stage/unpacked"
test -x "$stage/unpacked/$(basename "$archive" .tar.gz)/traffic-masq"
test -x "$stage/unpacked/$(basename "$archive" .tar.gz)/traffic-masqd"
printf '%s\n' "packaging staging smoke test passed"
