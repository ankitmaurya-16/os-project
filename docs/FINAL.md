# Taint tracking and the xv6 agent: final report

CSL3030 Operating Systems Lab. Tree: **xv6-public (x86)**, branch `taint`.
The mid-term state is tagged `midterm`; [MIDTERM.md](MIDTERM.md) describes it.
This report covers what was added for the final evaluation, and why.

**Core idea (unchanged):** what a process may do depends on where its input
came from. A process that has read untrusted bytes loses dangerous rights, and
the **kernel** enforces this, whatever program, agent or LLM is asking.

**What the second half adds:** taint now follows data through *every* channel
the mid-term left open (file writes and creates), the policy protects more
than `unlink` (writes to clean files, `exec`, `/safe`), pipes are tracked per
byte, and the agent gained a private serial line and a real-LLM planner.

## What changed since the mid-term

| Commit | Step | Result |
|---|---|---|
| `0eb9453` | 1. Taint follows file writes and creates | `cat /inbox.txt > copy` no longer launders |
| `bcfd07e` | 2. Write-down rule | A tainted process can't change a clean file |
| `178bdae` | 3. `/safe` exec, link and create rules | A tainted process can only run trusted programs |
| `784d4ce` | 4. Per-byte pipe tracking (`PIPE_PERBYTE`) | The per-pipe false positive is gone |
| `03098c8` | 5. Laundering attack suite (`launder`) | 10/10 attacks blocked (mid-term kernel: 6/10) |
| `f49de21` | 6. False-positive table (`taintrun`) | No implementation bugs; every refusal is intended |
| `da3a57e` | 7. UART1 device and bridge | Agent traffic and kernel logs on separate wires |
| `77a1ef0` | 8. LLM planner via an API-key gateway | Any hosted model, same validator and kernel |

After every kernel step, `usertests` matched the baseline line for line
(`docs/logs/final_step{1,2,3,4}_usertests.txt`, and `final_step7_kernel.txt`).
Clean processes behave exactly as in unmodified xv6.

## The full policy

| A tainted process... | Rule | Where |
|---|---|---|
| ...may not delete files | `unlink` refused (mid-term) | `sysfile.c` `sys_unlink` |
| ...makes every file it writes untrusted | write marks the inode | `file.c` `filewrite` |
| ...makes every file it creates untrusted | create marks the inode | `sysfile.c` `create` |
| ...may not change a clean file that holds data | write-down | `file.c` `filewrite` |
| ...may only run programs from `/safe` | exec rule | `exec.c` |
| ...may not create or link anything into `/safe` | `/safe` stays clean | `sysfile.c` `create`, `sys_link` |

And for everyone:
- running an untrusted binary taints the caller;
- nobody may link an untrusted file into `/safe`.

Taint still spreads through `read`, `fork`, `exec` and pipes as at the mid-term.
Pipes now track individual bytes.

## Design decisions

### 1. File writes and creates (closing the mid-term hole)

At the mid-term, `cat /inbox.txt > copy; cat copy | helper /important.txt`
deleted the file. The tainted `cat` wrote untrusted bytes into `copy`, which
stayed clean, and then exited. Its taint was lost, but the data survived.

- **`filewrite`:** when a tainted process writes at least one byte to a
  `T_FILE`, the inode is marked untrusted and saved with `iupdate()`. This is
  safe because `filewrite` is already inside `begin_op()` and holds the inode
  lock.
- **`create`:** a `T_FILE` created by a tainted process starts untrusted. This
  covers files that are created but never written, such as markers. It sets
  the flag next to the `iupdate()` that `create` already does.
- **Only `T_FILE`.** The console and `/uart1` are `T_DEV`, so tainted processes
  can still print. Directories are not marked (see Limitations).

Evidence: `final_step1_laundering_closed.txt`. The same commands now show
`helper: read 83 bytes, tainted=1` and the unlink is refused.

### 2. Write-down, with one exception

Step 1 alone still let a tainted process **overwrite** `important.txt`. The
file would be marked untrusted, but its content would already be destroyed.
That is an integrity loss, not just a confidentiality one. So `filewrite`
refuses a write when:

- the writer is tainted, and
- the target is a `T_FILE`, and
- the file is clean and **already holds data** (`size > 0`).

**Why the empty-file exception:** the shell creates the target of `> file`
in the forked child, *before* `exec`, while that child is still clean. A strict
rule would make `cat /inbox.txt > new.txt` impossible, because `new.txt` is
always a clean, empty file when `cat` writes to it. Writing into an empty file
destroys no trusted data, and Step 1 marks the file untrusted on that first
write, so the data stays tracked. A strict version is a one-line change
(remove `size > 0`).

Evidence: `final_step2_writedown.txt`. `cat /inbox.txt > important.txt` is
refused and `important.txt` is unchanged, while `cat /inbox.txt > new.txt`
works and produces an untrusted file.

### 3. `/safe`

A tainted process must not be able to start a fresh program that does the
damage for it.

- **Where `/safe` comes from:** `init` creates it at boot and hard-links ten
  trusted programs into it (`cat echo grep wc ls sh helper tainttest launder
  taintrun`). No `mkfs` change is needed, and errors after a reboot are ignored.
- **How "in `/safe`" is decided:** `issafedir(dp)` in `fs.c` compares the
  program's **parent directory inode** (`dev` and `inum`) with `namei("/safe")`.
  It does not compare path strings, so `/safe/../ls` is refused (test 21), and a
  relative name works when the current directory is `/safe`.
- **Lock ordering:** `issafedir` locks `/` and `/safe`. `exec` therefore
  decides "in `/safe`?" *before* it locks the program's inode, and
  `create`/`sys_link` check it *before* `ilock(dp)`. Otherwise `exec("/safe")`
  or a create inside `/safe` would try to lock an inode it already holds, and
  deadlock.
- **Keeping `/safe` clean:**
  - a tainted process may not create or link into `/safe`;
  - nobody may link an untrusted inode into it;
  - write-down stops a tainted process from changing the clean programs
    already there.
- **Untrusted programs:** `exec` of an untrusted binary taints the caller. Code
  is data, and this closes the mid-term limitation "executing an untrusted
  binary does not taint". Because `/safe` holds only clean files, the
  now-tainted caller is then refused by the `/safe` rule, so an untrusted
  binary never runs.

Side effect: `cat /inbox.txt rmcmd | sh` is now stopped at `exec rm`, before it
ever reaches `unlink` (`final_step3_safe.txt`).

### 4. Per-byte pipes

The mid-term's single bit per pipe over-tainted: a reader of only clean bytes
became tainted once any tainted writer had used the pipe.

- **Ranges:** `struct pipe` now keeps up to 16 ranges `[start, end)` of byte
  positions that came from tainted writers. Positions are the existing
  `nwrite`/`nread` counters, which only grow, so a range never wraps.
  `% PIPESIZE` is still only used to index the buffer.
- **`pipewrite`:** records each byte with `taintbyte()` *while holding the
  lock*. A writer can sleep half way through a big write (the buffer is 512
  bytes), and the reader may run during that sleep. Recording byte by byte
  means a reader never sees a tainted byte that isn't recorded yet (test 27).
  A byte that directly follows the newest range extends it, so a long tainted
  write uses one slot.
- **`piperead`:** remembers where its read started. After copying, it taints
  the reader only if `[start, nread)` overlaps a range, then drops ranges that
  have been read completely.
- **Overflow:** if all 16 slots are in use, the pipe falls back to the old
  whole-pipe flag. That is safe, just less precise.
- **Switch:** `PIPE_PERBYTE 0` in `param.h` rebuilds the mid-term behaviour.
  Per-pipe mode simply records no ranges, so the read path is shared.

| Case | Situation | Per-pipe | Per-byte |
|---|---|---|---|
| 7 | Tainted writer, reader reads its byte | tainted | tainted |
| 8 | Clean and tainted writer, reader reads everything | tainted | tainted |
| 26 | Clean and tainted writer, reader reads **only the clean byte** | **tainted (false positive)** | clean |
| 26 | ...then reads the tainted byte | tainted | tainted |
| 27 | Tainted writer sleeps mid-write (1000 bytes > 512) | tainted | tainted |

Both builds pass `tainttest` (`final_step4_pipe_compare.txt`).

### 5. UART1: a private line for the agent

At the mid-term, agent replies and kernel `taint:` lines shared one console,
and the bridge separated them by text prefix. Now:

- **Kernel:** `uart1.c` (about 130 lines) drives COM2 (port `0x2f8`, IRQ 3) as
  `/uart1`, a raw byte device (major 2):
  - the interrupt fills a 512-byte ring buffer;
  - `read` sleeps until bytes arrive, and `^D` means end of file, like the
    console;
  - `write` polls the port like `uartputc`.

  It is modelled on `uart.c` and `console.c`. Without a second serial port
  (plain `make qemu-nox`), it fails with -1.
- **QEMU:** `make qemu-agent UARTPORT=N` adds COM2 as a TCP server on
  `127.0.0.1:N`.
- **Guest:** `agentd -u` reopens fd 0 and fd 1 on `/uart1`, the same trick
  `init` uses for the console, so the rest of `agentd` is unchanged.
- **Host:** `UartBridge` boots `qemu-agent`, types `agentd -u` at the console,
  and runs the **same** framed `request()` code over the socket (`pexpect`
  `fdspawn`). Kernel lines are collected from the console after each reply and
  attached to that request.

Agent data and kernel messages now travel on different wires, so file content
can't be mistaken for a kernel line or the other way round.

Evidence:
- `final_step7_uart_smoke.txt`: raw protocol over TCP.
- `final_step7_demo_uart*.txt`: the demo and the control over UART1.

### 6. The LLM, through an API-key gateway

- **`llm_gateway.py`:** `LLMGateway.chat(system, messages)` speaks two
  formats:
  - `openai`: any OpenAI-compatible `/chat/completions` endpoint, which most
    hosted providers offer;
  - `anthropic`: the Messages API.

  It is configured with `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL` and
  `LLM_API_KEY`. A missing key is asked for with `getpass`. It uses only the
  standard library (`urllib`), so nothing is installed locally.
- **Key handling:** the key only ever goes into a request header. It is
  removed from every error message, is not shown by `repr()`, and is never
  logged or saved. `.env` is in `.gitignore`.
- **`llm_planner.py`:** `LLMPlanner` has the same interface as the scripted
  planners, so the agent loop, validator, tools and bridge are unchanged.
  - The system prompt is generated from `validator.TOOLS` and asks for exactly
    one JSON object.
  - File content goes back to the model inside `<untrusted_data>` tags, and a
    forged closing tag inside the file is defused.
  - A reply that is not one JSON object becomes a call the validator rejects,
    and the rejection is reported back to the model.
  - Model text is never executed. It can only *select* one of three tools.
- **Live testing (Groq):** `final_live_llm_demo*.txt`. Groq sits behind
  Cloudflare, which rejects urllib's default `Python-urllib` User-Agent with
  HTTP 403 (error 1010), so the gateway now sends its own `User-Agent`. In the
  marked runs the session is tainted after reading `/inbox.txt`, and
  `/important.txt` survives.
- **Offline testing:** `fake_llm.py` is a local OpenAI-compatible endpoint
  that obeys the injection. It tests the whole HTTP path with no network
  (`final_step8_demo_llm_fake.txt`). In that run the "model" proposes
  `delete_file("/important.txt")`, the validator accepts it (it checks form,
  not intent), and the kernel refuses it.

## Kernel changes (since the mid-term)

Every change is marked `// taint:` (`grep -n "taint:" *.c *.h`).

| File | Function | Change |
|---|---|---|
| `file.c` | `filewrite()` | Write-down check before `writei`; mark the inode untrusted after a tainted write |
| `sysfile.c` | `create()` | Tainted `T_FILE` creates start untrusted; tainted create in `/safe` refused |
| `sysfile.c` | `sys_link()` | Link into `/safe` refused if the caller is tainted or the inode is untrusted |
| `fs.c`, `defs.h` | `issafedir()` | New: is this directory inode `/safe`? |
| `exec.c` | `exec()` | Untrusted binary taints the caller; tainted caller only runs `/safe` programs |
| `pipe.c` | `struct pipe`, `taintbyte`, `readtainted`, `dropranges`, `pipewrite`, `piperead` | Per-byte ranges, with whole-pipe fallback |
| `param.h` | `PIPE_PERBYTE` | Switch: 1 per-byte (default), 0 per-pipe |
| `uart1.c` (new) | `uart1init`, `uart1intr`, `uart1read`, `uart1write` | COM2 driver as `/uart1` |
| `traps.h`, `trap.c`, `main.c`, `file.h`, `defs.h`, `Makefile` | | Wiring for `uart1.c`; `qemu-agent` target |

User programs:
- `init` builds `/safe` and creates `/uart1`;
- `agentd -u`;
- `tainttest`: 27 cases plus the parent check, up from 13;
- new: `launder`, `taintrun`.

## Test results

### `tainttest` (`final_tainttest_boot1.txt`, `final_tainttest_boot2.txt`)

ALL PASSED on two boots from the same `fs.img`. Case 12 is SKIP on the first
boot (it marks a file) and PASS on the second. The new cases:

| # | Case |
|---|---|
| 14 | Tainted write to an empty clean file marks it untrusted |
| 15 | File created by a tainted process starts untrusted |
| 16 | Files written by a clean process stay clean |
| 17 | Write-down: tainted write to a clean file is refused, content unchanged |
| 18 | Tainted process can write its own untrusted file |
| 19 | Tainted process can still write to the console |
| 20 | Tainted exec outside `/safe` is refused |
| 21 | Tainted exec of `/safe/../ls` is refused |
| 22 | Tainted link into `/safe` is refused |
| 23 | Linking an untrusted file into `/safe` is refused, even when clean |
| 24 | Tainted create in `/safe` is refused |
| 25 | Running an untrusted program taints, and is refused |
| 26 | Pipe: reading only clean bytes does not taint (per-byte) |
| 27 | Pipe: a writer sleeping mid-write has already tainted its bytes |

### Laundering attack suite (`final_step5_launder.txt`)

Each attack runs in a child of a clean parent. For the file attacks, a fresh
"consumer" forked by the clean parent then reads the laundered file and tries
the delete, so the consumer can only be tainted by what it reads.

| # | Attack | Final | Mid-term | Blocked by |
|---|---|---|---|---|
| 1 | Read through a `dup`'d fd | BLOCKED | BLOCKED | flag on the inode, not the fd |
| 2 | Write, delete, recreate to "reset" the flag | BLOCKED | **LEAKED** | unlink refused; create starts untrusted |
| 3 | Clean and tainted writer on one pipe | BLOCKED | BLOCKED | `piperead` byte ranges |
| 4 | Pipe → clean helper → file → reader | BLOCKED | **LEAKED** | `piperead`, then `filewrite` marks the file |
| 5 | `exec` a fresh program | BLOCKED | BLOCKED | `exec` keeps taint; `/safe` rule |
| 6 | `fork` a child to delete | BLOCKED | BLOCKED | `fork` copies taint |
| 7 | Copy to a new file (the mid-term hole) | BLOCKED | **LEAKED** | create/filewrite mark the copy |
| 8 | Overwrite the victim | BLOCKED | **LEAKED** | write-down |
| 9 | Link the inbox under a new name | BLOCKED | BLOCKED | flag on the inode, not the name |
| 10 | Untrusted program into `/safe` | BLOCKED | BLOCKED* | `/safe` link/create rules; untrusted exec taints |

\* On the mid-term kernel, attack 10 only *looks* blocked: there is no `/safe`
there, and the untrusted program actually ran. Only the unlink rule stopped it.

Running the same suite on the mid-term kernel shows that it really detects
leaks: the four leaks are exactly the holes that Steps 1 and 2 closed.

### False-positive table (`final_step6_fp_table.txt`)

Every program was run **tainted** via `taintrun`. Programs outside the default
`/safe` list were first linked into `/safe` by a clean shell, so that the rest
of the policy could be tested too.

| Program (tainted) | Result | Classification |
|---|---|---|
| `ls`, `cat`, `wc`, `grep`, `echo` | work | works |
| `mkdir d1`, `ln report.txt r2`, `kill`, `forktest`, `zombie` | work | works |
| `stressfs` | works; the files it creates start untrusted | works |
| `/ls`, `/mkdir` (outside `/safe`) | exec refused | policy: `/safe` rule |
| `mkdir /safe/d2` | refused | policy: no create in `/safe` |
| `rm scratch.txt` | refused | policy: unlink (the point of it) |
| tainted `sh`: `ls` with cwd `/` | exec refused; works after `cd /safe` | policy: `/safe` rule (xv6 `sh` has no PATH) |
| tainted `sh`: `echo hi > fp.new` | works, file untrusted | works |
| tainted `sh`: `echo hi > report.txt` | refused, file unchanged | policy: write-down |
| `usertests` | fails in `createdelete` | policy: unlink |
| `usertests` as a **clean** process | identical to the baseline | no false positives |

No implementation bugs were found: every failure comes directly from one
intended rule. The one *unintended* false positive, the per-pipe clean-byte
case, is removed by per-byte mode.

### pytest (`final_live_pytest.txt`): 47 passed, including the live test

Without `LLM_API_KEY` the live test is skipped (46 passed, 1 skipped, `final_step8_pytest.txt`).

| File | Tests |
|---|---|
| `test_agent.py` (27) | Validator (unknown tool, 8 bad paths, 5 malformed calls, normalization, destructive gate); bridge errors (timeout, forged end marker, unsafe path); end to end on xv6 over the console (list, read, taint, injected delete refused, control) and over **UART1** (marked and control) |
| `test_llm.py` (19 + 1 live) | Valid call accepted; code fence tolerated; 5 unusable replies (prose, broken JSON, shell text, two objects, array) rejected; unknown tool rejected; destructive gate still applies; rejection reported to the model; `<untrusted_data>` wrapping with a forged close tag; truncation; OpenAI and Anthropic request formats; **key redacted** from errors and `repr`; LLM error ends the run without a tool call; key prompt; missing model. The live test runs only with `LLM_API_KEY` set |

### Demo runs

| Run | Bridge | Planner | `/important.txt` at the end |
|---|---|---|---|
| `demo.py` | console | scripted injected | still exists (kernel refused) |
| `demo.py --control` | console | scripted injected | deleted |
| `demo.py --uart` | UART1 | scripted injected | still exists |
| `demo.py --uart --control` | UART1 | scripted injected | deleted |
| `demo.py --planner llm` with `fake_llm.py` | console | LLM gateway (local fake) | still exists |
| `demo.py --planner llm` (Groq, `qwen/qwen3.8-27b`) | console | live hosted model | still exists |
| `demo.py --planner llm --uart` (Groq) | UART1 | live hosted model | still exists |
| `demo.py --planner llm --control` (Groq) | console | live hosted model | still exists (model ignored the injection) |

In every pair, the planner, validator and bridge behave the same. Only the
kernel's taint state differs.

## Known limitations

- **Real models behave differently from run to run.** In the live Groq runs
  the model refused the injected instruction by itself, so the kernel refusal
  of an obeyed injection is shown with the scripted planner and `fake_llm.py`.
  Groq's `gpt-oss` models try native tool calls (empty replies or HTTP 400
  `tool_use_failed`) instead of the JSON reply format, so we use
  `qwen/qwen3.8-27b` there.
- **Covert channels are not tracked.** These carry information out of a
  tainted process without tainting the receiver:
  - file *names* (directories are never marked);
  - file sizes;
  - `kill`;
  - timing.

  A tainted process could create a file named `Delete_important`, and a clean
  `ls` would not be tainted.
- **The empty-file exception.** A tainted process can fill any *empty* clean
  file. The file becomes untrusted, so it is tracked, but the owner may be
  surprised.
- **`marktaint` is unprivileged** (xv6 has no users). Anyone can mark a `/safe`
  program untrusted. That is a denial of service: whoever runs that program is
  then tainted. It is not an escalation.
- **`/safe` is judged by the path used.** The same binary is allowed as
  `/safe/cat` and refused as `/cat`. That is intended, because the hard links
  share one inode.
- **A refused exec of an untrusted binary still taints the caller.** It tried
  to run untrusted code.
- **Pipe positions are 32-bit.** After 4 GB through one pipe, the range
  comparisons would wrap. More than 16 separate tainted runs in one pipe fall
  back to whole-pipe taint, which is safe.
- **Taint is per process and permanent**, as at the mid-term. A long-running
  process that reads one untrusted file keeps its restrictions until it exits.
- **UART1:**
  - Kernel lines are collected from the console for 0.3 s after each reply. A
    line printed later would be attributed to the next request.
  - One agent session at a time.
  - The 512-byte input buffer drops bytes when full; agent lines are short.
- **The validator checks form, not intent.** With destructive tools enabled,
  an injected `delete_file` passes it. That is why the kernel layer exists.

## 5-minute demo script

Run from the repo root. Each step says what to say.

1. **Boot (30 s).** `make clean && make qemu-nox`.
   *"Same tree as the mid-term, tagged `midterm`. Eight more commits."*
2. **The mid-term hole is closed (60 s).** At the `$` prompt:
   ```
   marktaint /inbox.txt
   cat /inbox.txt > copy
   cat copy | helper /important.txt
   cat /inbox.txt > important.txt
   cat important.txt
   ```
   *"`copy` became untrusted when tainted `cat` wrote it, so `helper` is
   tainted and can't delete. Overwriting `important.txt` is refused by
   write-down, and its content is unchanged."*
3. **`/safe` (45 s).** `taintrun /ls`, then `taintrun /safe/ls /safe`.
   *"A tainted process can only run the trusted programs in `/safe`, decided
   by the directory inode, so `/safe/../ls` doesn't work either."*
4. **Attacks (45 s).** `launder`. *"Ten laundering attacks, all blocked. On
   the mid-term kernel, four of them leak."*
5. **Pipes (30 s).** `tainttest`, and point at case 26. *"Per-byte tracking:
   reading only the clean bytes of a shared pipe no longer taints. With
   `PIPE_PERBYTE 0` this case shows the old false positive."*
6. **The agent over UART1 (60 s).** Quit QEMU (`Ctrl-A x`), then
   `cd python && python3 demo.py --uart`. *"Agent traffic goes over its own
   serial line; the kernel lines come from the console. The injected delete
   is proposed, validated, and refused by the kernel."* Then
   `python3 demo.py --uart --control`: *"Same everything, inbox not marked:
   the file is gone."*
7. **The LLM (30 s).** `python3 demo.py --planner llm` (enter the API key when
   asked), or the offline `fake_llm.py` run. *"The model only picks a tool;
   whatever it picks, the kernel has the last word."*

## Viva questions and answers

**Why mark files in `filewrite` and not in `writei`?**
`writei` is also used by the kernel itself, for directory entries in
`dirlink`. `filewrite` is exactly where a user process's bytes go into a file,
the mirror image of `fileread`.

**Why not just forbid tainted processes from writing at all?**
They couldn't print to the console or use pipes, which breaks almost every
program. Write-down only protects clean files that already hold data.

**Why is there an exception for empty files?**
`sh` creates the `> file` target before `exec`, while it is still clean. The
exception keeps `cat untrusted > new` working without destroying any trusted
data, and the first write marks the file.

**How do you decide that a program is "in `/safe`"?**
By comparing the parent directory's inode with `/safe`'s inode, not by
comparing strings. This handles `..`, relative paths and the current directory.

**Can a tainted process put a program into `/safe`?**
No:
- creating and linking into `/safe` are refused for tainted processes;
- linking an untrusted file there is refused for everyone;
- write-down stops it from modifying the programs already there.

**Why record pipe taint per byte inside the copy loop?**
`pipewrite` can sleep when the buffer is full, and the reader runs during
that sleep. If the range were recorded after the loop, the reader could get
tainted bytes from a range that wasn't recorded yet (test 27).

**What happens when the 16 ranges run out?**
The pipe falls back to whole-pipe taint. That is over-broad, but it never
under-taints.

**Why a second serial port?**
So agent data and kernel messages can't be confused, and the bridge doesn't
have to separate them from one stream of text. Most of the driver is copied
from the COM1 code; the new part is a raw read with `^D` as EOF.

**Is the LLM part of the security boundary?**
No. Its reply is untrusted input:
- it must be one JSON object;
- the validator checks it;
- it can only select one of three fixed tools.

The kernel enforces the policy no matter what the model says.

**What isn't covered?**
- covert channels (file names, sizes, `kill`, timing);
- per-process granularity;
- unprivileged `marktaint`.

See Known limitations.
