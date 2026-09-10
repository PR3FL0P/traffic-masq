#!/bin/sh
set -eu

destdir=${DESTDIR:-}
prefix=${PREFIX:-/usr/local}

# Keep DESTDIR staging removal independent of the host daemon.
if [ -z "$destdir" ]; then
    exec "$prefix/sbin/traffic-masqd" uninstall --prefix "$prefix" "$@"
fi

remove_file() {
    path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -f -- "$path"
    fi
}

remove_file "$destdir$prefix/sbin/traffic-masqd"
remove_file "$destdir$prefix/bin/traffic-masq"
remove_file "$destdir$prefix/share/doc/traffic-masq/README.md"
remove_file "$destdir$prefix/share/doc/traffic-masq/config.example.toml"

printf '%s\n' "Removed installed traffic-masq files."
printf '%s\n' "Preserved /etc/traffic-masq, /var/lib/traffic-masq, and /var/log/traffic-masq."
