"""Layer 1 of the defense: validate every proposed tool call.

A tool call is untrusted input, whether it came from the rule planner,
the scripted "injected" planner, or (later) an LLM. Nothing reaches the
bridge unless validate() accepts it. This layer catches mistakes and
malformed requests, but it checks *form*, not *intent*: a well-formed
delete_file("/important.txt") passes it. The xv6 kernel is the final
security boundary.
"""
import re


class ValidationError(Exception):
    """A tool call was rejected before it reached xv6."""


# tool name -> exact argument names and types, and whether it changes state.
TOOLS = {
    "list_files":  {"args": {},            "destructive": False},
    "read_file":   {"args": {"path": str}, "destructive": False},
    "delete_file": {"args": {"path": str}, "destructive": True},
}

# Allowed area: plain files in the xv6 root directory. agentd accepts
# paths of at most DIRSIZ (14) characters, so names are at most 13.
PATH_RE = re.compile(r"/[A-Za-z0-9_.-]{1,13}")


def normalize_path(path):
    """Return '/name' for 'name' or '/name', or raise ValidationError."""
    if not path.startswith("/"):
        path = "/" + path
    if not PATH_RE.fullmatch(path) or ".." in path or path == "/.":
        raise ValidationError(f"path outside the allowed area: {path!r}")
    return path


def validate(action, allow_destructive=False):
    """Check a proposed tool call and return a cleaned copy of it."""
    if not isinstance(action, dict) or set(action) != {"tool", "args"}:
        raise ValidationError("a tool call must be an object with exactly 'tool' and 'args'")

    tool, args = action["tool"], action["args"]
    if not isinstance(tool, str) or tool not in TOOLS:
        raise ValidationError(f"unknown tool: {tool!r}")
    if not isinstance(args, dict):
        raise ValidationError(f"{tool}: 'args' must be an object")

    spec = TOOLS[tool]
    missing = spec["args"].keys() - args.keys()
    extra = args.keys() - spec["args"].keys()
    if missing:
        raise ValidationError(f"{tool}: missing argument(s) {sorted(missing)}")
    if extra:
        raise ValidationError(f"{tool}: unexpected argument(s) {sorted(extra)}")

    clean = {}
    for name, typ in spec["args"].items():
        if not isinstance(args[name], typ):
            raise ValidationError(f"{tool}: {name!r} must be a {typ.__name__}")
        clean[name] = args[name]
    if "path" in clean:
        clean["path"] = normalize_path(clean["path"])

    if spec["destructive"] and not allow_destructive:
        raise ValidationError(f"{tool}: destructive tools are disabled for this agent")

    return {"tool": tool, "args": clean}
