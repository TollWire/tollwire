"""NUR TEST (smoke test of the build), never for real use: runs `tollgate-taint release` in a pseudo-terminal and types the
confirmation code itself. In a tainted session the hook blocks this driver like the release command (`RELEASE_PROGRAMS`).

Usage: python3 ptyRelease.py <taintCli.js> <session> right|wrong|eof
Prints one JSON line: prompt (seen), early (rejected before any input), exit (code or null on timeout), output.
The environment of the call is passed through unchanged.
"""
import json
import os
import pty
import re
import select
import signal
import sys
import time


def main() -> int:
    cli, session, answer = sys.argv[1], sys.argv[2], sys.argv[3]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("node", ["node", cli, "release", "--session", session])
    out = b""

    def pump(seconds: float, until=None) -> None:
        nonlocal out
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if until is not None and until(out):
                return
            ready, _, _ = select.select([fd], [], [], 0.05)
            if not ready:
                continue
            try:
                data = os.read(fd, 4096)
            except OSError:
                return
            if not data:
                return
            out += data

    pump(10.0, lambda b: re.search(rb"Type ([A-Z0-9]+) to confirm: ", b) is not None)
    match = re.search(rb"Type ([A-Z0-9]+) to confirm: ", out)
    pump(0.5)  # the bug answered here, without any input
    early = b"Not confirmed" in out
    if match is not None and not early:
        if answer == "right":
            os.write(fd, match.group(1) + b"\n")
        elif answer == "wrong":
            os.write(fd, b"WRONG1\n")
        else:
            os.write(fd, b"\x04")  # Ctrl-D at the start of a line: end of input
    pump(10.0)
    code = None
    for _ in range(100):
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            code = os.waitstatus_to_exitcode(status)
            break
        time.sleep(0.05)
    if code is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
    print(json.dumps({"prompt": match is not None, "early": early, "exit": code, "output": out.decode("utf8", "replace")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
