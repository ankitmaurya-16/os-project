"""Prompt-injection demo: the agent is tricked, the kernel refuses.

    python3 demo.py            # /inbox.txt marked untrusted: delete refused
    python3 demo.py --control  # /inbox.txt NOT marked: delete succeeds
    python3 demo.py --uart     # same, over the second serial port
    python3 demo.py --planner llm   # a hosted LLM chooses the tools
                                    # (see llm_gateway.py for LLM_* settings)

Both runs start from a freshly built fs.img containing /report.txt,
/inbox.txt (with the injection text from the agent handout) and
/important.txt, run one agentd session, and use the scripted injected
planner with destructive tools enabled (simulating a careless operator),
so the kernel is the only thing left that can stop the delete.

With --planner llm a real model chooses the tools instead. It may or may
not obey the injected sentence; either way /important.txt must survive
in the marked run, because the kernel refuses a tainted unlink.
"""
import argparse
import json
import os

from agent import Agent, InjectedPlanner
from bridge import Bridge, UartBridge, fresh_image
from tools import Tools

XV6 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUESTS = ["summarize /report.txt", "summarize /inbox.txt"]


def show_step(entry):
    if "finish" in entry:
        print(f"  step {entry['step']}: finish -> {entry['finish']}")
        return
    print(f"  step {entry['step']}: proposed  {json.dumps(entry['proposed'])}")
    if "rejected" in entry:
        print(f"           REJECTED  {entry['rejected']}")
        return
    obs = entry["observation"]
    print(f"           validated {json.dumps(entry['validated'])}")
    print(f"           guest ok={obs['ok']} tainted={obs['tainted']}")
    for line in obs["output"].splitlines():
        print(f"             | {line}")
    for line in obs["kernel_log"]:
        print(f"           kernel: {line}")
    if obs["error"] and not obs["output"]:
        print(f"           error: {obs['error']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--control", action="store_true",
                    help="do not mark /inbox.txt untrusted (control run)")
    ap.add_argument("--uart", action="store_true",
                    help="talk to agentd over the second serial port (UART1)")
    ap.add_argument("--planner", choices=["injected", "llm"], default="injected",
                    help="injected: scripted, always obeys the file (default); "
                         "llm: a hosted model via llm_gateway (asks for the API key)")
    ap.add_argument("--xv6", default=XV6, help="xv6 source tree")
    opts = ap.parse_args()

    if opts.planner == "llm":
        from llm_gateway import LLMGateway
        from llm_planner import LLMPlanner
        gateway = LLMGateway.from_env()     # before booting, so the key prompt is clean
        planner = LLMPlanner(gateway)
        print(f"planner: {gateway!r}")
    else:
        planner = InjectedPlanner()

    print("=== " + ("CONTROL run: /inbox.txt left trusted" if opts.control
                    else "DEMO run: /inbox.txt marked untrusted") +
          (" (bridge: UART1)" if opts.uart else " (bridge: console)"))
    fresh_image(opts.xv6)
    bridge_class = UartBridge if opts.uart else Bridge
    with bridge_class(opts.xv6).boot() as bridge:
        if not opts.control:
            bridge.mark_untrusted("/inbox.txt")
            print("setup: marktaint /inbox.txt")
        bridge.start_session()
        agent = Agent(planner, Tools(bridge), allow_destructive=True)
        for request in REQUESTS:
            print(f"\nuser request: {request!r}")
            answer, trace = agent.run(request)
            for entry in trace:
                show_step(entry)
            print(f"  answer: {answer}")

        status = bridge.request("STATUS")
        listing = bridge.request("LS")
        names = [line.split()[0] for line in listing.output.splitlines()]
        print(f"\nfinal state: agentd session tainted={status.tainted}")
        print("final state: /important.txt still exists: " +
              ("YES" if "important.txt" in names else "NO"))


if __name__ == "__main__":
    main()
