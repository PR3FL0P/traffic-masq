#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary_dir=${BINARY_DIR:-$project_dir/target/release}
prefix=${PREFIX:-/usr/local}
config=${TRAFFIC_MASQ_CONFIG:-/etc/traffic-masq/config.toml}
start=true
dry_run=false

usage() {
    cat <<'EOF'
Usage: sudo ./packaging/update.sh [options]

Update an existing installation from prepared binaries; no build or download.
Configuration, saved network settings, credentials and user access are retained.
Stopping the daemon follows its shutdown policy and may interrupt connectivity.

  --binary-dir DIR  Directory containing both new binaries (default: project target/release)
  --prefix PATH     Existing installation prefix (default: /usr/local)
  --config PATH     Existing configuration (default: /etc/traffic-masq/config.toml)
  --no-start        Leave the updated daemon stopped (not supported by runit)
  --dry-run         Validate inputs and describe the update without stopping it
  -h, --help        Show this help

BINARY_DIR, PREFIX and TRAFFIC_MASQ_CONFIG supply defaults for the corresponding
options. Custom prefix/configuration paths must match the existing installation.
EOF
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary-dir|--prefix|--config)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Missing value for $1"
            case "$1" in
                --binary-dir) binary_dir=$2 ;;
                --prefix) prefix=$2 ;;
                --config) config=$2 ;;
            esac
            shift 2
            ;;
        --no-start) start=false; shift ;;
        --dry-run) dry_run=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1 (use --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "Run update.sh as root, for example: sudo $0"
[ -z "${DESTDIR:-}" ] || fail "Updates do not support DESTDIR; use packaging/install.sh for staging."
case "$prefix" in
    /*) ;;
    *) fail "Installation prefix must be absolute." ;;
esac
case "/$prefix/" in
    */../*) fail "Installation prefix must not contain '..' components." ;;
esac
case "$config" in
    /*) ;;
    *) config=$PWD/$config ;;
esac
[ -f "$config" ] || fail "Existing configuration not found: $config. Use the installer for a new installation."
[ -d "$binary_dir" ] || fail "Binary directory not found: $binary_dir. Build both binaries or use --binary-dir."
binary_dir=$(CDPATH= cd -- "$binary_dir" && pwd)
installed_daemon=$prefix/sbin/traffic-masqd
[ -f "$installed_daemon" ] && [ -x "$installed_daemon" ] && [ ! -L "$installed_daemon" ] \
    || fail "Existing regular daemon executable not found: $installed_daemon"
for name in traffic-masqd traffic-masq; do
    [ -f "$binary_dir/$name" ] && [ -x "$binary_dir/$name" ] && [ ! -L "$binary_dir/$name" ] \
        || fail "Missing regular executable: $binary_dir/$name. Build both binaries or use --binary-dir."
    "$binary_dir/$name" --help >/dev/null
done

# Reject incompatible configuration or binaries before interrupting the service.
"$binary_dir/traffic-masqd" --config "$config" config validate
printf 'Update binaries from: %s\nInstallation prefix: %s\nConfiguration: %s\n' \
    "$binary_dir" "$prefix" "$config"
if "$dry_run"; then
    printf '%s\n' "Dry run: would stop the daemon and run its installer with the existing configuration and service backend."
    if "$start"; then
        printf '%s\n' "Would start the updated daemon and wait for readiness."
    else
        printf '%s\n' "Would leave the updated daemon stopped (runit requires startup)."
    fi
    exit 0
fi

# Keep service ownership, process locking and atomic binary replacement in the
# native installer. Do not copy over running executables or reset saved state.
"$installed_daemon" --config "$config" stop
set -- --config "$config" install --non-interactive --skip-user-access \
    --defer-password --prefix "$prefix" --init-system auto
if "$start"; then
    set -- "$@" --start
fi
if ! "$binary_dir/traffic-masqd" "$@"; then
    fail "Update failed. Installation may be partial; inspect the installer error and rerun with the same paths. No automatic rollback was attempted."
fi
printf '%s\n' "traffic-masq update completed."
