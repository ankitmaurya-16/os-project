"""Tool execution: map each *validated* tool call to one fixed agentd request."""
from bridge import BridgeError

# tool -> agentd verb. Arguments are passed as separate, validated fields;
# no shell string is ever built from model or file content.
VERBS = {
    "list_files": "LS",
    "read_file": "READ",
    "delete_file": "DELETE",
}


class Observation:
    """What a tool call returned to the agent."""

    def __init__(self, ok, output="", tainted=None, kernel_log=(), error=None):
        self.ok = ok
        self.output = output
        self.tainted = tainted
        self.kernel_log = list(kernel_log)
        self.error = error

    def as_dict(self):
        return {"ok": self.ok, "output": self.output, "tainted": self.tainted,
                "kernel_log": self.kernel_log, "error": self.error}


class Tools:
    def __init__(self, bridge):
        self.bridge = bridge

    def execute(self, action):
        """Run an action that validator.validate() already accepted."""
        verb = VERBS[action["tool"]]
        try:
            reply = self.bridge.request(verb, action["args"].get("path"))
        except BridgeError as e:
            return Observation(ok=False, error=str(e))
        return Observation(ok=reply.ok, output=reply.output, tainted=reply.tainted,
                           kernel_log=reply.kernel_log,
                           error=None if reply.ok else reply.output)
