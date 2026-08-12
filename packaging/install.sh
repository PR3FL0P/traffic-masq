#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
prefix=${PREFIX:-/usr}
binary_dir=${BINARY_DIR:-$project_dir/target/release}
access_group=${TRAFFIC_MASQ_GROUP:-traffic-masq}
config_path=${TRAFFIC_MASQ_CONFIG:-/etc/traffic-masq/config.toml}

if [ -z "$destdir" ] && [ "$(id -u)" -ne 0 ]; then
    printf '%s\n' "Run this installer as root so it can install files and configure daemon access." >&2
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

printf '%s\n' "Installed traffic-masq into ${destdir:-/}$prefix"
if [ -z "$destdir" ]; then
    if ! getent group "$access_group" >/dev/null 2>&1; then
        groupadd --system "$access_group"
        printf '%s\n' "Created system group $access_group."
    fi

    install_user=${TRAFFIC_MASQ_USER:-${SUDO_USER:-}}
    if [ -n "$install_user" ] && [ "$install_user" != root ]; then
        if id "$install_user" >/dev/null 2>&1; then
            usermod -aG "$access_group" "$install_user"
            printf '%s\n' "Granted $install_user access through group $access_group."
        else
            printf '%s\n' "Warning: user $install_user does not exist; group membership was not changed." >&2
        fi
    else
        printf '%s\n' \
            "No non-root install user detected; add one later with: usermod -aG $access_group USER"
    fi

    if [ ! -e "$config_path" ]; then
        "$prefix/sbin/traffic-masqd" config init --path "$config_path"
    fi

    if grep -Eq '^[[:space:]]*socket_group[[:space:]]*=' "$config_path"; then
        configured_group=$(sed -n \
            's/^[[:space:]]*socket_group[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
            "$config_path" | head -n 1)
        if [ "$configured_group" != "$access_group" ]; then
            printf '%s\n' \
                "Warning: $config_path already uses socket_group = \"$configured_group\"; left unchanged." >&2
        fi
    else
        config_tmp=$(mktemp "${config_path}.tmp.XXXXXX")
        trap 'rm -f -- "$config_tmp"' EXIT HUP INT TERM
        awk -v group="$access_group" '
            /^\[/ && in_runtime && !inserted {
                print "socket_group = \"" group "\""
                inserted = 1
            }
            /^\[runtime\][[:space:]]*$/ { in_runtime = 1 }
            { print }
            END {
                if (in_runtime && !inserted) {
                    print "socket_group = \"" group "\""
                }
            }
        ' "$config_path" > "$config_tmp"
        chmod 0640 "$config_tmp"
        chown --reference="$config_path" "$config_tmp"
        mv -f -- "$config_tmp" "$config_path"
        trap - EXIT HUP INT TERM
        printf '%s\n' "Configured socket_group = \"$access_group\" in $config_path."
    fi

    printf '%s\n' "Next: sudo $prefix/sbin/traffic-masqd start"
    if [ -n "$install_user" ] && [ "$install_user" != root ]; then
        printf '%s\n' \
            "Then sign out and back in (or run 'newgrp $access_group') before starting traffic-masq."
    fi
fi
