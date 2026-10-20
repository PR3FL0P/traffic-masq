"""Runs only inside the Rust test's private user/network/mount namespaces."""
import json
import subprocess
import sys


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True)


for ns, router_if, address in [("outside", "wan0", "198.51.100.2/24"), ("inside", "lan0", "192.0.2.2/24")]:
    run("ip", "netns", "add", ns)
    run("ip", "link", "add", router_if, "type", "veth", "peer", "name", "peer")
    run("ip", "link", "set", "peer", "netns", ns)
    run("ip", "link", "set", router_if, "up")
    run("ip", "-n", ns, "link", "set", "lo", "up")
    run("ip", "-n", ns, "addr", "add", address, "dev", "peer")
    run("ip", "-n", ns, "link", "set", "peer", "up")
run("ip", "addr", "add", "198.51.100.1/24", "dev", "wan0")
run("ip", "addr", "add", "198.51.100.9/24", "dev", "wan0")
run("ip", "addr", "add", "192.0.2.1/24", "dev", "lan0")
run("ip", "-n", "inside", "route", "add", "default", "via", "192.0.2.1")
run("ip", "-n", "outside", "addr", "add", "198.51.100.130/24", "dev", "peer")
run("ip", "-n", "outside", "route", "add", "192.0.2.0/24", "via", "198.51.100.1")
run("ip", "-n", "outside", "route", "add", "203.0.113.1/32", "via", "198.51.100.1")
with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
    f.write("1\n")

server = r'''
import socket, selectors
s = selectors.DefaultSelector()
for kind in [socket.SOCK_STREAM, socket.SOCK_DGRAM]:
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind(('192.0.2.2', 2222))
    if kind == socket.SOCK_STREAM: sock.listen()
    s.register(sock, selectors.EVENT_READ)
print('ready', flush=True)
while True:
    for key, _ in s.select():
        sock = key.fileobj
        if sock.type == socket.SOCK_STREAM:
            conn, addr = sock.accept()
            assert addr[0] in ('198.51.100.2', '198.51.100.130'), addr
            with conn: conn.sendall(conn.recv(128))
        else:
            data, addr = sock.recvfrom(128)
            assert addr[0] in ('198.51.100.2', '198.51.100.130'), addr
            sock.sendto(data, addr)
'''
client = r'''
import socket, sys
protocol, source, address, port, expected = sys.argv[1:]
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
sock.settimeout(0.4)
sock.bind((source, 0))
success = False
try:
    sock.connect((address, int(port)))
    sock.sendall(b'port-forward-probe')
    success = sock.recv(128) == b'port-forward-probe'
except OSError: pass
assert success == (expected == 'yes'), (protocol, source, address, port, expected, success)
'''
proc = subprocess.Popen(["ip", "netns", "exec", "inside", "python3", "-u", "-c", server], stdout=subprocess.PIPE, text=True)
try:
    assert proc.stdout.readline().strip() == "ready"
    for protocol in ["tcp", "udp"]:
        for source, destination, port, expected in [
            ("198.51.100.2", "198.51.100.1", 8443, True),
            ("198.51.100.2", "198.51.100.9", 8443, sys.argv[1] != "scoped"),
            ("198.51.100.130", "198.51.100.1", 8443, sys.argv[1] != "scoped"),
            ("198.51.100.2", "198.51.100.1", 8444, False),
            ("198.51.100.2", "192.0.2.2", 2222, False),
            ("198.51.100.2", "203.0.113.1", 8443, False),
        ]:
            run("ip", "netns", "exec", "outside", "python3", "-c", client, protocol, source, destination, str(port), "yes" if expected else "no")

    # Keep the configured egress present, but route the target through another
    # interface. Even broad sharing must not override a mapping's `to` constraint.
    run("ip", "link", "set", "lan0", "down")
    run("ip", "link", "set", "lan0", "name", "other0")
    run("ip", "link", "set", "other0", "up")
    run("ip", "link", "add", "lan0", "type", "dummy")
    run("ip", "link", "set", "lan0", "up")
    run("nft", "add", "rule", "inet", "traffic_masq", "forward",
        "meta", "nfproto", "ipv4", "iifname", '"wan0"', "oifname", '"other0"', "accept")
    try:
        for protocol in ["tcp", "udp"]:
            # Direct traffic proves the new route and the sharing permission work.
            for address, port, expected in [("192.0.2.2", "2222", "yes"),
                                             ("198.51.100.1", "8443", "no")]:
                run("ip", "netns", "exec", "outside", "python3", "-c", client,
                    protocol, "198.51.100.2", address, port, expected)
    finally:
        # Restore the exact owned rules before Rust checks their integrity.
        entries = json.loads(run("nft", "-j", "-a", "list", "chain",
                                 "inet", "traffic_masq", "forward").stdout)["nftables"]
        handle = [entry["rule"]["handle"] for entry in entries if "rule" in entry][-1]
        run("nft", "delete", "rule", "inet", "traffic_masq", "forward", "handle", str(handle))
finally:
    proc.terminate()
    proc.wait(timeout=3)
