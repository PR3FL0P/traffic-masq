#!/bin/sh
# Build as the current user; elevate only tests that change the selected radio.
set -eu

usage() {
    printf '%s\n' 'Usage: sh packaging/test-wifi-physical.sh --interface NAME [--suite functional|inspect|client|ap] [--ssid SSID --psk-file /absolute/path] [--sudo]' 'Default suite: functional (real scan and static IPv4; requires root).'
}
interface=
suite=functional
ssid=
psk_file=
use_sudo=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        --interface|--suite|--ssid|--psk-file)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            case "$1" in
                --interface) interface=$2 ;;
                --suite) suite=$2 ;;
                --ssid) ssid=$2 ;;
                --psk-file) psk_file=$2 ;;
            esac
            shift 2 ;;
        --sudo) use_sudo=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[ -n "$interface" ] || { usage >&2; exit 2; }
case "$suite" in
    inspect) target=wifi_physical; test_name=selected_adapter_matches_sysfs_and_nl80211 ;;
    functional) target=wifi_client_physical; test_name=physical_tui_ ;;
    client) target=wifi_client_physical; test_name=physical_wpa2_client_associates_without_touching_management_uplink ;;
    ap) target=wifi_ap_physical; test_name=physical_wpa2_ap_serves_a_station_without_touching_management_uplink ;;
    *) usage >&2; exit 2 ;;
esac
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    # An outer sudo removes the invoking user's Cargo PATH. Restart as that
    # user before creating build artifacts, retaining elevation only for I/O
    # that actually changes the radio.
    script_path=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
    set -- --interface "$interface" --suite "$suite"
    if [ "$suite" != inspect ]; then
        set -- "$@" --ssid "$ssid" --psk-file "$psk_file" --sudo
    fi
    printf 'Building as %s; only physical test execution needs root.\n' "$SUDO_USER" >&2
    exec sudo -H -u "$SUDO_USER" -- sh -c '
        PATH="$HOME/.cargo/bin:$PATH"
        export PATH
        exec sh "$@"
    ' wifi-physical "$script_path" "$@"
fi
if [ "$suite" != inspect ]; then
    if [ "$suite" != functional ]; then
        [ -n "$ssid" ] && [ -n "$psk_file" ] || {
            printf '%s\n' 'client/ap suites require --ssid and --psk-file (regular file, mode 0600).' >&2
            exit 2
        }
    fi
    if [ "$(id -u)" -ne 0 ]; then
        "$use_sudo" || { printf '%s\n' 'Use --sudo for functional/client/ap execution.' >&2; exit 2; }
        sudo -n true
    fi
elif "$use_sudo"; then
    printf '%s\n' 'inspect runs without sudo.' >&2
    exit 2
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
cargo test --locked --no-run --test "$target" --message-format=json > "$stage/build.jsonl"
executable=$(python3 - "$stage/build.jsonl" "$target" "$test_name" "$suite" <<'PY'
import json
import subprocess
import sys
artifacts = [message["executable"] for line in open(sys.argv[1])
             if (message := json.loads(line)).get("reason") == "compiler-artifact"
             and message.get("target", {}).get("name") == sys.argv[2]
             and message.get("profile", {}).get("test")
             and message.get("executable")]
if len(artifacts) != 1:
    raise RuntimeError("expected exactly one test executable")
args = [artifacts[0], sys.argv[3], "--ignored", "--list"]
expected = [sys.argv[3]]
if sys.argv[4] == "functional":
    expected = ["physical_tui_scan_discovers_real_networks",
                "physical_tui_static_ipv4_reaches_the_kernel"]
else:
    args.append("--exact")
listing = subprocess.run(args,
                         check=True, capture_output=True, text=True).stdout
found = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
if sorted(found) != sorted(expected):
    raise RuntimeError(f"physical test selection mismatch: expected {expected}, found {found}")
print(artifacts[0])
PY
)
set -- env "TRAFFIC_MASQ_WIFI_INTERFACE=$interface"
case "$suite" in
    client) set -- "$@" "TRAFFIC_MASQ_WIFI_SSID=$ssid" "TRAFFIC_MASQ_WIFI_PSK_FILE=$psk_file" ;;
    ap) set -- "$@" "TRAFFIC_MASQ_AP_SSID=$ssid" "TRAFFIC_MASQ_AP_PSK_FILE=$psk_file" ;;
esac
if "$use_sudo"; then
    set -- sudo -n "$@"
fi
if [ "$suite" = functional ]; then
    "$@" "$executable" "$test_name" --ignored --test-threads=1 --nocapture
else
    "$@" "$executable" "$test_name" --exact --ignored --test-threads=1 --nocapture
fi
