"""Tool definitions and validation for the xv6 agent.

Every proposed tool call is treated as untrusted input, no matter where it
came from (rule planner, LLM, or a test). validate_action() is the single
gate: nothing reaches xv6 unless it passes here.
"""
import re


class ToolError(Exception):
    """A tool call was rejected before it reached xv6."""


# tool name -> argument names/types, and whether it changes guest state.
TOOLS = {
    "list_files":  {"args": {},             "destructive": False},
    "read_file":   {"args": {"path": str},  "destructive": False},
    "summarize":   {"args": {"text": str},  "destructive": False},
    "delete_file": {"args": {"path": str},  "destructive": True},
}

# xv6 file names: root directory only, at most 13 chars (DIRSIZ is 14).
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,13}")
MAX_TEXT = 4096


def normalize_path(path):
    """Turn '/inbox.txt' or 'inbox.txt' into 'inbox.txt', or reject it."""
    if path.startswith("/"):
        path = path[1:]
    if path in (".", "..") or not NAME_RE.fullmatch(path):
        raise ToolError(f"path not allowed: {path!r}")
    return path


def validate_action(action):
    """Check a proposed tool call and return a cleaned copy of it."""
    if not isinstance(action, dict) or set(action) != {"tool", "args"}:
        raise ToolError("action must be an object with exactly 'tool' and 'args'")

    tool, args = action["tool"], action["args"]
    if not isinstance(tool, str) or tool not in TOOLS:
        raise ToolError(f"unknown tool: {tool!r}")
    if not isinstance(args, dict):
        raise ToolError("args must be an object")

    spec = TOOLS[tool]["args"]
    missing = spec.keys() - args.keys()
    extra = args.keys() - spec.keys()
    if missing:
        raise ToolError(f"{tool}: missing argument(s) {sorted(missing)}")
    if extra:
        raise ToolError(f"{tool}: unexpected argument(s) {sorted(extra)}")

    clean = {}
    for name, typ in spec.items():
        if not isinstance(args[name], typ):
            raise ToolError(f"{tool}: {name!r} must be a {typ.__name__}")
        clean[name] = args[name]

    if "path" in clean:
        clean["path"] = normalize_path(clean["path"])
    if "text" in clean and len(clean["text"]) > MAX_TEXT:
        raise ToolError(f"{tool}: text longer than {MAX_TEXT} characters")

    return {"tool": tool, "args": clean}


def confirm(action, auto_confirm=False, ask=input):
    """Require a human 'yes' before any destructive action.

    auto_confirm=True simulates a careless user who approves everything;
    the demo uses it to show that the kernel still has the final say.
    """
    if not TOOLS[action["tool"]]["destructive"] or auto_confirm:
        return
    answer = ask(f"Agent wants to run {action}. Allow? [y/N] ")
    if answer.strip().lower() != "y":
        raise ToolError(f"{action['tool']}: not confirmed by user")
