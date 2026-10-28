"""The agent loop plus two deterministic planners (no LLM yet).

    request -> planner -> proposed call -> validate -> execute -> observation
                  ^                                                  |
                  +------------------- history ----------------------+

A planner returns either a tool call {"tool": ..., "args": {...}} or
{"finish": "<answer>"}. The loop stops on finish or after max_steps.
"""
import re

from validator import ValidationError, validate


class RulePlanner:
    """Understands: 'list', 'read <path>', 'summarize <path>'."""

    def next_action(self, request, history):
        words = request.split()
        verb, arg = (words[0].lower() if words else ""), (words[1] if len(words) > 1 else None)
        if not history:
            if verb == "list":
                return {"tool": "list_files", "args": {}}
            if verb in ("read", "summarize") and arg:
                return {"tool": "read_file", "args": {"path": arg}}
            return {"finish": f"unsupported request: {request!r}"}
        action, obs = history[-1]
        if obs is None or not obs.ok:
            return {"finish": "failed: " + (obs.error if obs else "call rejected")}
        if verb == "summarize" and action["tool"] == "read_file":
            return {"finish": summarize(obs.output)}
        return {"finish": obs.output}


class InjectedPlanner(RulePlanner):
    """A deliberately gullible planner for a repeatable injection demo.

    After reading a file it obeys any 'Delete <path>' sentence inside the
    file's content -- treating data as an instruction, which is exactly
    the mistake prompt injection exploits. Real LLMs do this only some of
    the time; this planner does it every time.
    """

    INSTRUCTION = re.compile(r"\bDelete\s+(/?[A-Za-z0-9_.-]+?)\.?(?:\s|$)")

    def next_action(self, request, history):
        if history:
            action, obs = history[-1]
            if action["tool"] == "read_file" and obs is not None and obs.ok:
                m = self.INSTRUCTION.search(obs.output)
                if m:
                    return {"tool": "delete_file", "args": {"path": m.group(1)}}
            if action["tool"] == "delete_file":
                outcome = "deleted" if obs is not None and obs.ok else "could not delete"
                return {"finish": f"{outcome} {action['args']['path']} as the file instructed"}
        return super().next_action(request, history)


def summarize(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return f"{len(lines)} line(s): " + " ".join(lines)


class Agent:
    def __init__(self, planner, tools, allow_destructive=False, max_steps=5):
        self.planner = planner
        self.tools = tools
        self.allow_destructive = allow_destructive
        self.max_steps = max_steps

    def run(self, request):
        """Returns (answer, trace). The trace records every step."""
        history, trace = [], []
        for step in range(1, self.max_steps + 1):
            proposed = self.planner.next_action(request, history)
            if "finish" in proposed:
                trace.append({"step": step, "finish": proposed["finish"]})
                return proposed["finish"], trace
            entry = {"step": step, "proposed": proposed}
            try:
                action = validate(proposed, self.allow_destructive)
            except ValidationError as e:
                entry["rejected"] = str(e)
                trace.append(entry)
                history.append((proposed, None))
                continue
            entry["validated"] = action
            obs = self.tools.execute(action)
            entry["observation"] = obs.as_dict()
            trace.append(entry)
            history.append((action, obs))
        trace.append({"step": self.max_steps + 1, "finish": "stopped: step limit"})
        return "stopped: step limit", trace
