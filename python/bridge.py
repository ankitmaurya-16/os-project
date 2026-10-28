"""Host-to-QEMU bridge: drives xv6's serial console with pexpect.

Method: start `make qemu-nox` (the serial console on stdio), wait for the
xv6 shell prompt, then start the guest utility `agentd` and talk to it
with a line protocol:

    host -> guest   <id> LS | <id> READ <path> | <id> DELETE <path> | <id> STATUS
    guest -> host   @@BEGIN <id>
                    ...output (and any "taint: ..." kernel log lines)...
                    @@END <id> <OK|ERR> tainted=<0|1>

<id> is a fresh random hex string per request, so file content printed by
READ cannot forge the end marker. pexpect accumulates output until the
whole framed reply has arrived, so replies split across reads are fine,
and the echoed request line is skipped because it never contains
"@@BEGIN <id>". A timeout or a missing marker raises BridgeError: the
bridge never invents success.

The only strings ever typed into the guest are built here from a fixed
verb and a path that matches PATH_RE. No model or file content is ever
sent to a host shell; pexpect runs `make` with an argument list.

UartBridge (below) speaks the same protocol over the guest's second
serial port instead, via `make qemu-agent` and a local TCP socket.
"""
import re
import secrets
import socket
import subprocess
import time

import pexpect
from pexpect import fdpexpect

VERBS = {"LS", "READ", "DELETE", "STATUS"}
PATH_RE = re.compile(r"/[A-Za-z0-9_.-]{1,13}")
PROMPT = r"\n\$ "
EOF_PROMPT = r"\x04\$ "   # after Ctrl-D, xv6 echoes ^D and then prints the prompt
KERNEL_LOG_PREFIX = "taint:"


class BridgeError(Exception):
    """The guest did not produce a well-formed reply in time."""


class Reply:
    """One framed agentd reply, split into output and kernel log lines."""

    def __init__(self, request_id, ok, tainted, lines):
        self.id = request_id
        self.ok = ok
        self.tainted = tainted
        self.kernel_log = [l for l in lines if l.startswith(KERNEL_LOG_PREFIX)]
        self.output = "\n".join(l for l in lines if not l.startswith(KERNEL_LOG_PREFIX))

    def __repr__(self):
        return f"Reply(ok={self.ok}, tainted={self.tainted}, output={self.output!r}, kernel_log={self.kernel_log})"


def fresh_image(xv6_dir):
    """Rebuild fs.img from the repo's files, discarding guest changes."""
    subprocess.run(["rm", "-f", "fs.img"], cwd=xv6_dir, check=True)
    subprocess.run(["make", "fs.img"], cwd=xv6_dir, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Bridge:
    def __init__(self, xv6_dir, timeout=15, child=None):
        """With child=None, boot() starts QEMU. Tests may pass an already
        running pexpect child that stands in for an agentd session."""
        self.xv6_dir = xv6_dir
        self.timeout = timeout
        self.child = child
        self.in_session = child is not None
        self.transcript = []   # everything the guest printed, for the run log

    # -- lifecycle ---------------------------------------------------------

    def boot(self):
        self.child = pexpect.spawn("make", ["qemu-nox"], cwd=self.xv6_dir,
                                   encoding="utf-8", codec_errors="replace",
                                   timeout=self.timeout)
        self.child.logfile_read = _Collector(self.transcript)
        self._expect(r"init: starting sh\r?" + PROMPT, "boot", timeout=60)
        return self

    def close(self):
        if self.child is None:
            return
        try:
            if self.in_session:
                self.end_session()
            self.child.sendcontrol("a")
            self.child.send("x")          # QEMU monitor: quit
            self.child.expect(pexpect.EOF, timeout=10)
        except (pexpect.ExceptionPexpect, BridgeError):
            pass
        finally:
            self.child.close(force=True)
            self.child = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- shell-level setup (fixed commands only) ---------------------------

    def mark_untrusted(self, path):
        """Run `marktaint <path>` at the xv6 shell (outside any session)."""
        if self.in_session:
            raise BridgeError("mark_untrusted must run at the shell, not inside agentd")
        _check_path(path)
        self.child.sendline(f"marktaint {path}")
        self._expect(re.escape(f"marktaint: {path} is now untrusted"), "marktaint")
        self._expect(PROMPT, "marktaint")

    def start_session(self):
        """Start one agentd process; every request until end_session() runs in it."""
        self.child.sendline("agentd")
        self._expect(r"@@READY\r?\n", "agentd start")
        self.in_session = True

    def end_session(self):
        self.child.sendcontrol("d")       # EOF on agentd's stdin
        self.in_session = False
        self._expect(EOF_PROMPT, "agentd exit")

    # -- requests ----------------------------------------------------------

    def request(self, verb, path=None):
        if not self.in_session:
            raise BridgeError("no agentd session")
        if verb not in VERBS:
            raise BridgeError(f"unknown verb {verb!r}")
        if path is not None:
            _check_path(path)
        rid = secrets.token_hex(4)
        line = f"{rid} {verb}" + (f" {path}" if path is not None else "")
        chan = self._line()
        chan.sendline(line)
        self._expect(rf"@@BEGIN {rid}\r?\n(.*?)@@END {rid} (OK|ERR) tainted=([01])\r?\n",
                     f"reply to {line!r}", on=chan)
        body, status, tainted = chan.match.groups()
        lines = [l for l in body.replace("\r", "").split("\n") if l]
        return Reply(rid, status == "OK", tainted == "1", lines)

    # -- helpers -----------------------------------------------------------

    def _line(self):
        """The channel agentd talks on: the console here."""
        return self.child

    def _expect(self, pattern, what, timeout=None, on=None):
        try:
            (on or self.child).expect(re.compile(pattern, re.DOTALL),
                                      timeout=timeout or self.timeout)
        except pexpect.TIMEOUT:
            raise BridgeError(f"timeout waiting for {what}") from None
        except pexpect.EOF:
            raise BridgeError(f"guest exited while waiting for {what}") from None


class UartBridge(Bridge):
    """The same protocol, but agentd talks over the second serial port.

    `make qemu-agent` connects the guest's COM2 (/uart1) to a local TCP
    port. The console (COM1) is still used to boot, run marktaint and
    start `agentd -u`, and it is where the kernel prints its `taint:`
    lines; agent requests and replies go over the socket only, so file
    content and kernel messages can never be mixed on one wire.
    """

    LOG_WAIT = 0.3   # seconds to collect kernel lines after each reply

    def __init__(self, xv6_dir, timeout=15):
        super().__init__(xv6_dir, timeout)
        self.port = None
        self.sock = None
        self.line = None

    def boot(self):
        self.port = _free_port()
        self.child = pexpect.spawn("make", ["qemu-agent", f"UARTPORT={self.port}"],
                                   cwd=self.xv6_dir, encoding="utf-8",
                                   codec_errors="replace", timeout=self.timeout)
        self.child.logfile_read = _Collector(self.transcript)
        self._expect(r"init: starting sh\r?" + PROMPT, "boot", timeout=60)
        try:
            self.sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        except OSError as e:
            raise BridgeError(f"cannot connect to the guest's uart1 line: {e}") from None
        self.line = fdpexpect.fdspawn(self.sock.fileno(), encoding="utf-8",
                                      codec_errors="replace", timeout=self.timeout)
        self.line.logfile_read = _Collector(self.transcript)
        return self

    def start_session(self):
        self.child.sendline("agentd -u")
        self._expect(r"serving on /uart1", "agentd -u start")
        self._expect(r"@@READY\r?\n", "agentd ready on uart1", on=self.line)
        self.in_session = True

    def end_session(self):
        self.line.send("\x04")            # EOF on agentd's stdin (/uart1)
        self.in_session = False
        self._expect(r"\$ ", "agentd exit")   # the shell prompt on the console

    def request(self, verb, path=None):
        reply = super().request(verb, path)
        reply.kernel_log += self._drain_console()
        return reply

    def close(self):
        if self.sock is not None:
            try:
                if self.in_session:
                    self.end_session()
            except BridgeError:
                pass
            self.in_session = False
            self.sock.close()
            self.sock = None
        super().close()

    def _line(self):
        return self.line

    def _drain_console(self):
        """Collect `taint:` lines the kernel printed on the console."""
        text = ""
        deadline = time.time() + self.LOG_WAIT
        while time.time() < deadline:
            try:
                text += self.child.read_nonblocking(4096, timeout=0.05)
            except pexpect.TIMEOUT:
                continue
            except pexpect.EOF:
                break
        return [l.strip() for l in text.replace("\r", "").split("\n")
                if l.strip().startswith(KERNEL_LOG_PREFIX)]


def _free_port():
    """A local TCP port nobody is listening on (for QEMU's COM2)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _check_path(path):
    if not isinstance(path, str) or not PATH_RE.fullmatch(path) or ".." in path:
        raise BridgeError(f"refusing to send path {path!r}")


class _Collector:
    """File-like sink for pexpect's logfile_read."""

    def __init__(self, parts):
        self.parts = parts

    def write(self, s):
        self.parts.append(s)

    def flush(self):
        pass
