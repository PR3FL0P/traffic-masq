"""Rootless terminal smoke checks. Run: python3 tests/tui_pty.py [TUI binary].

Uses a temporary mock Unix API; never starts the daemon or changes networking.
"""
import fcntl
import json
import os
import pty
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time


def serve(listener, stopped):
    logins = []
    def connection(peer):
        with peer:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = peer.recv(4096)
                if not chunk:
                    return
                data += chunk
            path = data.split(b" ")[1]
            status = b"200 OK"
            if path == b"/api/v1/interfaces" and len(logins) >= 2:
                # A healthy socket that never supplies its HTTP response.
                stopped.wait(20)
                return
            if path == b"/api/v1/interfaces":
                status = b"401 Unauthorized"
                body = {"message": "session revoked"}
            elif path == b"/api/v1/auth/status":
                body = {"initialized": True}
            elif path == b"/api/v1/auth/login":
                logins.append(True)
                body = {
                    "token": "mock-token",
                    "principal": {"user_id": 1, "username": "device", "role": "administrator"},
                    "idle_expires_at": 9999999999,
                    "absolute_expires_at": 9999999999,
                }
            else:
                body = {}
            encoded = json.dumps(body).encode()
            peer.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                         + str(len(encoded)).encode() + b"\r\n\r\n" + encoded)

    listener.settimeout(0.1)
    while not stopped.is_set():
        try:
            peer, _ = listener.accept()
        except socket.timeout:
            continue
        threading.Thread(target=connection, args=(peer,), daemon=True).start()


def read_until(master, expected, timeout=5):
    output = b""
    plain = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            output += os.read(master, 65536)
            # Ratatui skips blank cells using cursor positioning instead of printing spaces.
            plain = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", lambda m: b" " if m.group().endswith(b"H") else b"", output)
            if expected in b" ".join(plain.split()):
                return output
    raise AssertionError(f"terminal did not display {expected!r}: {plain[-1000:]!r}")


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/debug/traffic-masq")
    with tempfile.TemporaryDirectory(prefix="traffic-masq-tui-") as directory:
        listener = socket.socket(socket.AF_UNIX)
        path = os.path.join(directory, "mock.sock")
        listener.bind(path)
        listener.listen()
        stopped = threading.Event()
        server = threading.Thread(target=serve, args=(listener, stopped), daemon=True)
        server.start()
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        child = subprocess.Popen([binary, "--socket", path], stdin=slave, stdout=slave,
                                 stderr=slave, preexec_fn=controlling_terminal,
                                 env={**os.environ, "XDG_STATE_HOME": directory})
        try:
            read_until(master, b"Device password:")
            os.write(master, b"mock-password-only\r")
            read_until(master, b"Session expired or revoked")
            os.write(master, b"mock-password-only\r")
            read_until(master, b"Refreshing")
            # Resizing must interrupt the stalled refresh and disable hidden actions.
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 10, 40, 0, 0))
            import signal
            child.send_signal(signal.SIGWINCH)
            read_until(master, b"Terminal too small")
            os.write(master, b"q")
            assert child.wait(timeout=3) == 0
            after = termios.tcgetattr(slave)
            assert after == before, "terminal mode was not restored"
            print("TUI PTY smoke passed: reauthentication, stalled API, responsive resize/exit, terminal restoration")
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=3)
            stopped.set()
            server.join(timeout=1)
            listener.close()
            os.close(master)
            os.close(slave)


if __name__ == "__main__":
    main()
