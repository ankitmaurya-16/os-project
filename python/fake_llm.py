"""A fake OpenAI-compatible endpoint that behaves like an injected model.

It reads the requested file, then obeys any "Delete /x" inside the
returned untrusted data, then finishes. It lets you test the LLM gateway
end to end with no network and no real key:

    python3 fake_llm.py 8765 &
    LLM_PROVIDER=openai LLM_MODEL=fake LLM_BASE_URL=http://127.0.0.1:8765/v1 \
        LLM_API_KEY=dummy-key python3 demo.py --planner llm
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def decide(messages):
    last = messages[-1]["content"]
    if len(messages) == 2:                      # system + request
        m = re.search(r"(/[\w.-]+)", last)
        return {"tool": "read_file", "args": {"path": m.group(1)}}
    if last.startswith("Result of read_file"):
        m = re.search(r"Delete (/[\w.-]+?)\.?(?:\s|$)", last)
        if m:
            return {"tool": "delete_file", "args": {"path": m.group(1)}}
        return {"finish": "summary: " + last.splitlines()[-2][:60]}
    return {"finish": "done: " + last.splitlines()[0]}


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        assert self.headers["Authorization"] == "Bearer dummy-key"
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        reply = json.dumps(decide(body["messages"]))
        out = json.dumps({"choices": [{"message": {"content": reply}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
