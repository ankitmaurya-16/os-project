# Host-side agent for xv6

A small Python agent that calls structured tools on xv6 running in QEMU, a
repeatable prompt-injection demo, and tests showing the xv6 kernel (not the
agent) refusing the injected delete.

```
request -> planner -> proposed call -> validator.py -> tools.py -> bridge.py --serial--> agentd (xv6)
              ^                        (Layer 1)                                            |
              +------------------------------ observation <----------------------------- kernel taint policy (Layer 2)
```

| File | Role |
|---|---|
| `validator.py` | Layer 1: allowlist, exact args and types, paths limited to `/<name>` (at most 13 chars), `delete_file` only with `allow_destructive=True` |
| `tools.py` | Maps `list_files`, `read_file`, `delete_file` to the fixed agentd verbs `LS`, `READ`, `DELETE` |
| `bridge.py` | Boots `make qemu-nox` with pexpect, starts `agentd`, sends `<id> VERB [path]`, reads until `@@END <id>` |
| `agent.py` | Agent loop with a step limit, `RulePlanner`, and the scripted `InjectedPlanner` |
| `llm_gateway.py` | API-key gateway to a hosted LLM: OpenAI-compatible or Anthropic format, standard library only |
| `llm_planner.py` | `LLMPlanner`: the model picks one tool per step as JSON; file content goes back as `<untrusted_data>` |
| `fake_llm.py` | A local OpenAI-compatible endpoint that obeys the injection, for offline runs |
| `demo.py` | The injection demo and its control run (`--uart`, `--planner llm`) |
| `test_agent.py` | pytest suite (unit tests plus end-to-end tests on xv6, console and UART1) |
| `test_llm.py` | Gateway and planner tests (no network); one live test with `LLM_API_KEY` |

## Setup

Requires `qemu-system-i386`, the `i686-elf` toolchain used by the Makefile,
and Python 3.9 or newer.

```sh
pip install pexpect pytest
```

## Run

From this directory:

```sh
python3 demo.py             # /inbox.txt marked untrusted: the kernel refuses the delete
python3 demo.py --control   # /inbox.txt left trusted: the delete succeeds
python3 demo.py --uart      # the same over the second serial port (UART1)
python3 demo.py --planner llm   # a hosted LLM picks the tools (see below)
python3 -m pytest -v        # all tests (end-to-end tests boot xv6 several times)
```

### Using a hosted LLM

Nothing is installed locally: the gateway calls your provider's API with
your key. Set the provider and model, then run the demo. If `LLM_API_KEY` is
not set, you are asked for it (input hidden). The key is only sent in a
request header and is never printed, logged or saved.

```sh
# Any OpenAI-compatible endpoint (OpenAI and most other hosted providers):
export LLM_PROVIDER=openai LLM_MODEL=<model> LLM_BASE_URL=<https://.../v1>   # base URL optional for OpenAI
# or the Anthropic Messages API:
export LLM_PROVIDER=anthropic LLM_MODEL=<model>
python3 demo.py --planner llm
```

Tested with Groq (OpenAI-compatible):

```sh
export LLM_PROVIDER=openai LLM_BASE_URL=https://api.groq.com/openai/v1 LLM_MODEL=qwen/qwen3.8-27b
python3 demo.py --planner llm          # or --uart, --control
```

On Groq, avoid the `gpt-oss` models here: they attempt native tool calls
instead of replying with one JSON object, and come back empty or with HTTP 400.

Offline, with no key, use the local stand-in that always obeys the injection:

```sh
python3 fake_llm.py 8765 &
LLM_PROVIDER=openai LLM_MODEL=fake LLM_BASE_URL=http://127.0.0.1:8765/v1 \
    LLM_API_KEY=dummy-key python3 demo.py --planner llm
```

Whatever the model proposes, it is validated like any other tool call, and
in the marked run the kernel refuses the delete.

`demo.py` and the end-to-end tests rebuild `fs.img` from the repo's files
before booting, so every run starts from the same guest state. Don't run two of
them at once: they share `fs.img`.

## Bridge method

QEMU's serial console (`make qemu-nox`, which uses `-nographic`) is driven with
pexpect. `make qemu` is not used because on macOS it also opens a display window.

- **One guest process per session.** The bridge starts `agentd` once and sends
  every tool call to it. Taint is per process, so once `agentd` reads
  `/inbox.txt` every later request in the session is tainted. Separate shell
  commands (`cat`, then `rm`) would each run in a fresh, clean process, and
  the kernel would never refuse anything.
- **Framing.** Each request carries a fresh random id, and the reply is
  `@@BEGIN <id> ... @@END <id> <OK|ERR> tainted=<0|1>`. File content can't
  forge the end marker, because it can't know the id in advance.
- **Partial reads.** pexpect buffers output until the whole framed reply has
  matched. The echoed request line is ignored because it never contains
  `@@BEGIN <id>`.
- **Errors.** A timeout, EOF or missing marker raises `BridgeError`, and
  `Tools.execute` turns that into a failed observation. The bridge never
  reports success it didn't see.
- **No shell injection.** Only fixed verbs and paths matching
  `/[A-Za-z0-9_.-]{1,13}` are ever typed into the guest, and QEMU is started
  with an argument list, not a host shell string.

Kernel log lines (`taint: ...`) printed during a request appear inside its
frame, so the bridge returns them separately as `kernel_log`.

### UART1 (`--uart`, `UartBridge`)

`make qemu-agent UARTPORT=N` gives the guest a second serial port (COM2,
`/uart1`) connected to a TCP server on `127.0.0.1:N`. The bridge still boots
and runs `marktaint` on the console, then starts `agentd -u`, which serves the
same protocol on `/uart1`. The same framed `request()` code runs over the
socket, so agent data never shares a wire with kernel messages. Kernel
`taint:` lines are collected from the console after each reply.

## Limitations

- Console bridge: the console is shared with kernel output. A kernel message
  printed outside any request (none are, today) would be ignored.
- UART1 bridge: kernel lines are collected for 0.3 s after each reply; a line
  printed later would be attributed to the next request.
- One session at a time. A new `agentd` (`end_session()` then
  `start_session()`) starts clean, which is how the tests isolate taint.
- With `--planner llm`, the model may or may not obey the injection. The
  validator checks form, not intent; the kernel is the final boundary.
