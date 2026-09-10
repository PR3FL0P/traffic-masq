"""Rootless session-persistence check: python3 tests/tui_session_pty.py [TUI binary]."""
import fcntl
import json
import os
import pathlib
import pty
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

from tui_pty import read_until


def serve(listener, stop, logins):
    listener.settimeout(0.1)
    while not stop.is_set():
        try:
            peer, _ = listener.accept()
        except socket.timeout:
            continue
        with peer:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = peer.recv(4096)
                if not chunk:
                    break
                data += chunk
            if not data:
                continue
            path = data.split(b" ")[1]
            status = b"200 OK"
            if path == b"/api/v1/auth/status":
                body = {"initialized": True}
            elif path == b"/api/v1/auth/login":
                logins.append(True)
                body = {"token": "mock-token", "principal": {"user_id": 1, "username": "device", "role": "administrator"},
                        "idle_expires_at": 9999999999, "absolute_expires_at": 9999999999}
            elif path == b"/api/v1/security/settings":
                if b"authorization: Bearer mock-token" not in data:
                    status, body = b"401 Unauthorized", {"message": "authentication required"}
                else:
                    body = {"type": "security_config", "active": {"rollback_timeout_seconds": 30},
                            "desired": {"rollback_timeout_seconds": 30}, "override_active": False, "restart_required": False}
            elif path == b"/api/v1/interfaces":
                body = {"type": "interfaces", "interfaces": []}
            else:
                body = {}
            encoded = json.dumps(body).encode()
            peer.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                         + str(len(encoded)).encode() + b"\r\n\r\n" + encoded)


def main():
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/debug/traffic-masq")
    with tempfile.TemporaryDirectory(prefix="traffic-masq-session-") as directory:
        socket_path = os.path.join(directory, "api.sock")
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(socket_path)
        listener.listen()
        stop, logins = threading.Event(), []
        thread = threading.Thread(target=serve, args=(listener, stop, logins), daemon=True)
        thread.start()

        def launch(action):
            master, slave = pty.openpty()
            before = termios.tcgetattr(slave)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
            child = subprocess.Popen([binary, "--socket", socket_path], stdin=slave, stdout=slave, stderr=slave,
                                     env={**os.environ, "XDG_STATE_HOME": directory})
            try:
                action(master)
                assert child.wait(timeout=5) == 0
                assert termios.tcgetattr(slave) == before
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=5)
                os.close(master)
                os.close(slave)

        def sign_in(master):
            read_until(master, b"Device password:")
            os.write(master, b"mock-password-only")
            masked = read_until(master, b"*")
            assert b"mock-password-only" not in masked
            os.write(master, b"\r")
            read_until(master, b"Dashboard")

        def first(master):
            sign_in(master)
            os.write(master, b"\x1b")

        def settings(master):
            os.write(master, b"\x1b[D")
            time.sleep(0.1)
            os.write(master, b"\x1b[D")
            read_until(master, b"Current process:")

        try:
            launch(first)
            assert len(logins) == 1
            cache = next(pathlib.Path(directory).glob("traffic-masq/client/*.session.json"))
            saved = json.loads(cache.read_text())
            assert cache.stat().st_mode & 0o777 == 0o600

            def cached(master):
                output = read_until(master, b"Dashboard")
                assert b"Device password:" not in output
                settings(master)
                # Rollback -> remember toggle -> duration; set two minutes, then save.
                os.write(master, b"\x1b[B\x1b[B\x7f2\x1b[B\r")
                read_until(master, b"Session preferences saved")
                os.write(master, b"\x1b")
                time.sleep(0.1)
                os.write(master, b"\x1b")

            launch(cached)
            assert len(logins) == 1, "a valid saved session should avoid a second login"
            prefs_path = next(pathlib.Path(directory).glob("traffic-masq/client/*.preferences.json"))
            assert json.loads(prefs_path.read_text()) == {"remember": True, "minutes": 2}
            current = json.loads(cache.read_text())
            assert current["authenticated_at"] == saved["authenticated_at"]
            current["authenticated_at"] = int(time.time()) - 121
            cache.write_text(json.dumps(current))

            def expired(master):
                sign_in(master)
                settings(master)
                os.write(master, b"\x1b[B\r\x1b[B\x1b[B\r")
                read_until(master, b"will require a password")
                os.write(master, b"\x1b")
                time.sleep(0.1)
                os.write(master, b"\x1b")

            launch(expired)
            assert len(logins) == 2
            assert not cache.exists()
            assert json.loads(prefs_path.read_text())["remember"] is False

            def disabled(master):
                read_until(master, b"Device password:")
                os.write(master, b"\x1b")

            launch(disabled)
            assert len(logins) == 2
            print("Session PTY passed: masked login, reuse, configurable duration, expiry, disabling, terminal restoration")
        finally:
            stop.set()
            thread.join(timeout=1)
            listener.close()


if __name__ == "__main__":
    main()
