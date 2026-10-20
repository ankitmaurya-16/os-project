# Code map: where taint tracking hooks into xv6-public (x86)

This tree is the flat x86 **xv6-public**, not xv6-riscv. All sources live in the
repo root (no `kernel/` or `user/`), the kernel prints with `cprintf`, user
syscall stubs are generated from `usys.S` (`SYSCALL(name)`), syscalls return
`int`, and `BSIZE` is 512, so `IPB` (inodes per block) is 8 with a 64-byte
`struct dinode`. Line numbers refer to the baseline commit.

Taint state lives on three kernel objects:

| Object | Field (planned) | Lives in |
|---|---|---|
| File (inode) | `uint untrusted` | `struct dinode` on disk, mirrored in `struct inode` |
| Process | `int tainted` | `struct proc` |
| Pipe | `int tainted` | `struct pipe` |

## fs.c

**`ilock(ip)`** (fs.c:288). Acquires the inode's sleep-lock and, the first time
the cached inode is used (`ip->valid == 0`), reads its `struct dinode` from the
inode block and copies `type`, `major`, `minor`, `nlink`, `size` and `addrs`
into the in-memory inode. *Taint:* copy `dip->untrusted` into `ip->untrusted`
here (disk to memory). Everything that reads the flag afterwards holds this lock.

**`iupdate(ip)`** (fs.c:221). Write-through of an in-memory inode back to its
on-disk `dinode`, via `log_write`, so it must run inside a `begin_op`/`end_op`
transaction. Caller holds `ip->lock`. *Taint:* copy `ip->untrusted` into
`dip->untrusted` (memory to disk). This is what makes `marktaint` persistent.

**`ialloc(dev, type)`** (fs.c:195). Scans the inode blocks for a dinode with
`type == 0`, `memset`s the whole dinode to zero, sets its type, logs the block
and returns the cached inode via `iget` (with `valid == 0`, so the next `ilock`
reloads it from disk). *Taint:* no change needed; the `memset` already clears
`untrusted`, so newly created files start trusted. Worth asserting in tests.

**`iput(ip)`** (fs.c:332). Drops a reference. If this was the last reference
and `nlink == 0`, it frees the inode: `itrunc`, `type = 0`, `iupdate`,
`valid = 0`. *Taint:* set `ip->untrusted = 0` just before that `iupdate`, so a
deleted-then-recreated file never inherits the old flag (also defended by
`ialloc`'s `memset`; doing both is belt and braces for the hidden test
"file written then deleted then recreated").

## file.c

**`fileread(f, addr, n)`** (file.c:97). Dispatches by file type: `FD_PIPE` goes
to `piperead`; `FD_INODE` takes `ilock`, calls `readi` at `f->off`, advances the
offset by the bytes read, and unlocks. *Taint:* in the `FD_INODE` branch, after
`readi` returns `> 0`, if `f->ip->untrusted` then set `myproc()->tainted = 1`
(logging the first time). The inode lock is already held, so no extra locking.
The flag is checked on the **inode**, not on `struct file`, so `dup`'d fds and
fds inherited across `fork` (which share one `struct file`) behave correctly.
Taint goes here rather than in `readi`, because `readi` is also used by `exec`
(exec.c:33, 44), `loaduvm` (vm.c:213) and directory scans (sysfile.c:175),
which are kernel-internal reads, not data flowing to the process.

**`filewrite(f, addr, n)`** (file.c:118). `FD_PIPE` goes to `pipewrite`;
`FD_INODE` writes in chunks, each in its own `begin_op`/`ilock`/`writei`/
`end_op`. *Taint:* none in the first half. Second half: a tainted writer marks
the inode untrusted (`ip->untrusted = 1; iupdate(ip)` inside the existing
transaction), and the write-down rule would refuse writes to clean files here.

## pipe.c

**`pipewrite(p, addr, n)`** (pipe.c:79). Under `p->lock`, copies bytes into the
`PIPESIZE` ring buffer, sleeping while full and failing if the read end closed
or the writer was killed. *Taint:* if `myproc()->tainted`, set `p->tainted = 1`
(per-pipe tracking, deliberately over-broad).

**`piperead(p, addr, n)`** (pipe.c:101). Under `p->lock`, sleeps while empty and
the write end is open, then copies out up to `n` bytes and wakes writers;
returns the number of bytes copied. *Taint:* after the copy loop, if `i > 0` and
`p->tainted`, set `myproc()->tainted = 1`.

**`pipealloc`** (pipe.c:23, not in the requested list but needed). Allocates
`struct pipe` with `kalloc()`, which does **not** zero memory (it fills freed
pages with junk). It initialises each field explicitly, so *taint:* add
`p->tainted = 0` here, or every new pipe could start randomly tainted.

## proc.c

**`allocproc()`** (proc.c:74). Finds an `UNUSED` slot in `ptable.proc`, marks it
`EMBRYO`, assigns a pid, allocates the kernel stack and sets up the trap frame
and context so the process starts in `forkret`. Used by both `fork` and
`userinit`. *Taint:* set `p->tainted = 0` where the slot is claimed, so a reused
slot never carries old taint.

**`fork()`** (proc.c:181). Allocates a child with `allocproc`, copies the
address space (`copyuvm`), trap frame, open files (`filedup`, so parent and
child **share** each `struct file`), cwd and name, then marks it `RUNNABLE`.
*Taint:* `np->tainted = curproc->tainted` before the `RUNNABLE` store, so no
other CPU can run the child before it has its taint.

**`freeproc()`**: **does not exist in xv6-public.** A zombie's slot is freed
inline in **`wait()`** (proc.c:273, freeing at about lines 290-300: `kfree`
kstack, `freevm`, clear `pid`/`parent`/`name`/`killed`, `state = UNUSED`).
*Taint:* also clear `p->tainted = 0` there, next to `p->killed = 0`, so the slot
is clean both when freed and when allocated.

## sysfile.c

**`sys_unlink()`** (sysfile.c:185). Fetches the path, then in one transaction
finds the parent directory, refuses `.`/`..`, looks up the entry, refuses
non-empty directories, zeroes the directory entry, decrements `nlink` and
`iput`s (which frees the inode if it was the last link and reference).
*Taint:* at the very top, if `myproc()->tainted`, print
`taint: unlink refused for pid %d` and return -1, before any `begin_op`, so
there's nothing to unwind.

**`sys_open()`** (sysfile.c:286). With `O_CREATE` calls `create`; otherwise
`namei` + `ilock`, refusing to open a directory for writing. Then allocates a
`struct file` and fd and records the inode, offset and mode. *Taint:* none.
Opening an untrusted file deliberately does **not** taint: only bytes actually
read do (tainttest case 4).

**`create(path, type, major, minor)`** (sysfile.c:242). Returns the existing
inode if a regular file already exists (for `O_CREATE` on a file); otherwise
`ialloc`s a new inode, sets `nlink = 1`, adds `.`/`..` for directories and
links it into the parent. *Taint:* none in the first half. Second half: a file
created by a tainted process starts `untrusted = 1`.

## exec.c

**`exec(path, argv)`** (exec.c:11). Loads an ELF from the inode with `readi`
into a fresh page table, builds the user stack, then commits by swapping in the
new page table and freeing the old one. It changes `sz`, `pgdir`, `name` and the
trap frame, but no other `struct proc` field. *Taint:* no change; taint survives
`exec` automatically because the process (and its `tainted` field) is the same.
Because `exec` uses `readi` directly, exec'ing an untrusted binary does not
taint (noted as a limitation). Second half: a tainted process may only exec
from `/safe`; that check belongs right after `namei`.
