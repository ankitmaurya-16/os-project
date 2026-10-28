"""Tests for the validator, agent, bridge and the kernel policy end to end.

Unit tests run anywhere. Tests marked `guest` boot xv6 in QEMU (a few
seconds each) and are skipped if qemu-system-i386 is not installed.
"""
import os
import shutil

import pexpect
import pytest

from agent import Agent, InjectedPlanner, RulePlanner
from bridge import Bridge, BridgeError, UartBridge, fresh_image
from tools import Tools
from validator import ValidationError, validate

XV6 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
guest = pytest.mark.skipif(shutil.which("qemu-system-i386") is None,
                           reason="qemu-system-i386 not installed")


class RecordingTools:
    """Stands in for Tools; fails the test if anything is executed."""

    def __init__(self):
        self.calls = []

    def execute(self, action):
        self.calls.append(action)
        raise AssertionError(f"should not reach the guest: {action}")


# -- validator (Layer 1) ----------------------------------------------------

def test_unknown_tool_rejected():
    with pytest.raises(ValidationError, match="unknown tool"):
        validate({"tool": "run_shell", "args": {"cmd": "rm -rf /"}})


def test_unknown_tool_never_reaches_guest():
    class Planner:
        def next_action(self, request, history):
            return {"finish": "done"} if history else {"tool": "format_disk", "args": {}}

    tools = RecordingTools()
    _, trace = Agent(Planner(), tools).run("anything")
    assert tools.calls == []
    assert "unknown tool" in trace[0]["rejected"]


@pytest.mark.parametrize("path", ["../README", "/a/b", "/..", "/.", "", "/",
                                  "/x;rm important.txt", "/averyverylongname.txt"])
def test_bad_path_rejected(path):
    with pytest.raises(ValidationError):
        validate({"tool": "read_file", "args": {"path": path}})


@pytest.mark.parametrize("action", [
    {"tool": "read_file", "args": {}},                           # missing
    {"tool": "read_file", "args": {"path": "/a", "mode": "w"}},  # extra
    {"tool": "read_file", "args": {"path": 5}},                  # wrong type
    {"tool": "list_files"},                                      # no args
    "read_file /inbox.txt",                                      # not an object
])
def test_malformed_call_rejected(action):
    with pytest.raises(ValidationError):
        validate(action)


def test_path_is_normalized():
    assert validate({"tool": "read_file", "args": {"path": "inbox.txt"}}) == \
        {"tool": "read_file", "args": {"path": "/inbox.txt"}}


def test_delete_needs_allow_destructive():
    call = {"tool": "delete_file", "args": {"path": "/important.txt"}}
    with pytest.raises(ValidationError, match="destructive"):
        validate(call)
    assert validate(call, allow_destructive=True)["tool"] == "delete_file"


# -- bridge error handling --------------------------------------------------

def test_timeout_returns_error():
    # `cat` echoes the request but never sends @@END: must time out, not succeed.
    child = pexpect.spawn("cat", encoding="utf-8")
    try:
        bridge = Bridge(XV6, timeout=1, child=child)
        with pytest.raises(BridgeError, match="timeout"):
            bridge.request("LS")
        obs = Tools(bridge).execute({"tool": "list_files", "args": {}})
        assert obs.ok is False and "timeout" in obs.error
    finally:
        child.close(force=True)


def test_forged_end_marker_is_not_accepted():
    # Output that ends with a marker for a *different* id must not match.
    child = pexpect.spawn("sh", ["-c", "read line; echo '@@BEGIN 0000'; "
                                       "echo '@@END 0000 OK tainted=0'; sleep 5"],
                          encoding="utf-8")
    try:
        with pytest.raises(BridgeError, match="timeout"):
            Bridge(XV6, timeout=2, child=child).request("LS")
    finally:
        child.close(force=True)


def test_bridge_refuses_unsafe_path():
    bridge = Bridge(XV6, child=pexpect.spawn("cat", encoding="utf-8"))
    try:
        with pytest.raises(BridgeError, match="refusing"):
            bridge.request("READ", "/x\nDELETE /important.txt")
    finally:
        bridge.child.close(force=True)


# -- end to end on xv6 ------------------------------------------------------

# The control and UART tests boot their own guests, so they come first:
# pytest sets up the module-scoped marked_guest at its first use and keeps it
# running until the end of the module, and two QEMUs must not share fs.img.

@guest
def test_control_delete_succeeds_when_inbox_trusted():
    fresh_image(XV6)
    with Bridge(XV6).boot() as bridge:
        bridge.start_session()
        agent = Agent(InjectedPlanner(), Tools(bridge), allow_destructive=True)
        _, trace = agent.run("summarize /inbox.txt")
        delete = next(e for e in trace if e.get("validated", {}).get("tool") == "delete_file")
        assert delete["observation"]["ok"] is True
        assert "important.txt" not in bridge.request("LS").output


@guest
@pytest.mark.parametrize("mark", [True, False], ids=["marked", "control"])
def test_uart_bridge_end_to_end(mark):
    # Same agent and protocol over the second serial port (UART1).
    fresh_image(XV6)
    with UartBridge(XV6).boot() as bridge:
        if mark:
            bridge.mark_untrusted("/inbox.txt")
        bridge.start_session()
        agent = Agent(InjectedPlanner(), Tools(bridge), allow_destructive=True)
        _, trace = agent.run("summarize /inbox.txt")
        read, delete = trace[0]["observation"], trace[1]["observation"]
        assert "Delete /important.txt" in read["output"]
        assert read["tainted"] is mark and delete["ok"] is not mark
        if mark:
            # Kernel lines come from the console, attributed to the request.
            assert any("tainted by reading inode" in l for l in read["kernel_log"])
            assert any("unlink refused" in l for l in delete["kernel_log"])
        assert ("important.txt" in bridge.request("LS").output) is mark


@pytest.fixture(scope="module")
def marked_guest():
    """One boot from a fresh fs.img with /inbox.txt marked untrusted."""
    fresh_image(XV6)
    bridge = Bridge(XV6).boot()
    bridge.mark_untrusted("/inbox.txt")
    yield bridge
    bridge.close()


@pytest.fixture
def session(marked_guest):
    """A fresh agentd process (clean taint state) for each test."""
    marked_guest.start_session()
    yield marked_guest
    marked_guest.end_session()


@guest
def test_list_succeeds(session):
    answer, trace = Agent(RulePlanner(), Tools(session)).run("list")
    obs = trace[0]["observation"]
    assert obs["ok"] and obs["tainted"] is False
    assert "report.txt" in answer and "important.txt" in answer


@guest
def test_read_trusted_succeeds(session):
    answer, trace = Agent(RulePlanner(), Tools(session)).run("read /report.txt")
    assert "100 requests" in answer
    assert trace[0]["observation"]["tainted"] is False


@guest
def test_read_untrusted_taints_session(session):
    _, trace = Agent(RulePlanner(), Tools(session)).run("read /inbox.txt")
    obs = trace[0]["observation"]
    assert obs["ok"] and obs["tainted"] is True
    assert any("tainted by reading inode" in l for l in obs["kernel_log"])


@guest
def test_injected_delete_refused_by_kernel(session):
    agent = Agent(InjectedPlanner(), Tools(session), allow_destructive=True)
    _, trace = agent.run("summarize /inbox.txt")
    delete = next(e for e in trace if e.get("validated", {}).get("tool") == "delete_file")
    assert delete["observation"]["ok"] is False
    assert any("unlink refused" in l for l in delete["observation"]["kernel_log"])
    # Benign operations still work after taint.
    listing = session.request("LS")
    assert listing.ok and "important.txt" in listing.output
