// tainttest: tests for kernel taint tracking.
//
// Taint is never cleared, so every case runs in its own child process
// and the parent stays clean. A child reports success by creating the
// file tt.ok; the parent only stat()s it, so no data (and no taint)
// flows back to the parent. Scratch files are removed by the clean
// parent, because a tainted child is not allowed to unlink.
//
// xv6-public's exit() takes no status, so the result is the summary
// line at the end rather than an exit code.

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "param.h"   // PIPE_PERBYTE: which pipe result case 26 expects

#define CLEAN   "tt.clean"    // trusted file
#define UNTR    "tt.untr"     // file marked untrusted
#define VICTIM  "tt.victim"   // file a tainted process tries to delete
#define PERSIST "tt.persist"  // marked on the first run, checked after reboot
#define OKFILE  "tt.ok"       // created by a child whose case passed

static char *scratch[] = { OKFILE, "tt.go", "tt.before", "tt.after", "tt.tmp", "tt.re",
                         "tt.w", "tt.c", "tt.bin", "/safe/tt.l", 0 };
static int fails;

static int
exists(char *path)
{
  struct stat st;

  return stat(path, &st) == 0;
}

static void
touch(char *path)
{
  int fd;

  if((fd = open(path, O_CREATE | O_RDWR)) >= 0)
    close(fd);
}

static void
mkfile(char *path, char *data)
{
  int fd;

  unlink(path);
  if((fd = open(path, O_CREATE | O_RDWR)) < 0){
    printf(1, "tainttest: cannot create %s\n", path);
    exit();
  }
  write(fd, data, strlen(data));
  close(fd);
}

// Read some bytes of path. Returns the byte count, or -1.
static int
readfile(char *path)
{
  char buf[64];
  int fd, n;

  if((fd = open(path, O_RDONLY)) < 0)
    return -1;
  n = read(fd, buf, sizeof(buf));
  close(fd);
  return n;
}

// The file's untrusted flag via fstat (no read, so no taint), or -1.
static int
untrusted(char *path)
{
  struct stat st;
  int fd;

  if((fd = open(path, O_RDONLY)) < 0)
    return -1;
  fstat(fd, &st);
  close(fd);
  return st.untrusted;
}

// Poll with stat (which never taints) until path exists.
static void
waitfor(char *path)
{
  while(!exists(path))
    sleep(1);
}

static void
cleanup(void)
{
  char **p;

  for(p = scratch; *p; p++)
    unlink(*p);
}

static void
report(int num, char *name, int ok)
{
  printf(1, "%d %s %s\n", num, ok ? "PASS" : "FAIL", name);
  if(!ok)
    fails++;
}

// Run fn in a fresh child of the (clean) parent.
static void
run(int num, char *name, int (*fn)(void))
{
  int pid;

  cleanup();
  if((pid = fork()) < 0){
    printf(1, "tainttest: fork failed\n");
    exit();
  }
  if(pid == 0){
    if(fn())
      touch(OKFILE);
    exit();
  }
  wait();
  report(num, name, exists(OKFILE));
  cleanup();
}

// 1
static int
t_fresh(void)
{
  return istainted() == 0;
}

// 2
static int
t_read_clean(void)
{
  return readfile(CLEAN) > 0 && istainted() == 0;
}

// 3
static int
t_read_untrusted(void)
{
  return istainted() == 0 && readfile(UNTR) > 0 && istainted() == 1;
}

// 4
static int
t_open_only(void)
{
  struct stat st;
  int fd;

  if((fd = open(UNTR, O_RDONLY)) < 0)
    return 0;
  fstat(fd, &st);
  close(fd);
  return st.untrusted == 1 && istainted() == 0;
}

// 5: the "before" child is forked while we are clean and checks only
// after we are tainted (tt.go), so it proves taint does not leak to
// existing children; the "after" child must inherit it.
static int
t_fork(void)
{
  int ok;

  if(fork() == 0){
    waitfor("tt.go");
    if(istainted() == 0)
      touch("tt.before");
    exit();
  }
  ok = readfile(UNTR) > 0 && istainted() == 1;
  touch("tt.go");
  if(fork() == 0){
    if(istainted() == 1)
      touch("tt.after");
    exit();
  }
  wait();
  wait();
  return ok && exists("tt.before") && exists("tt.after");
}

// 6: become tainted, then exec this program in report mode
// (see main), which creates tt.ok only if it is still tainted.
static int
t_exec(void)
{
  char *argv[] = { "tainttest", "-exec-child", 0 };

  if(readfile(UNTR) <= 0)
    return 0;
  exec("/safe/tainttest", argv);  // tainted: only /safe programs run
  return 0;
}

// 7
static int
t_pipe(void)
{
  int p[2], ok;
  char c;

  if(pipe(p) < 0)
    return 0;
  if(fork() == 0){
    close(p[0]);
    readfile(UNTR);
    write(p[1], "x", 1);
    exit();
  }
  close(p[1]);
  ok = istainted() == 0;
  ok = ok && read(p[0], &c, 1) == 1 && istainted() == 1;
  close(p[0]);
  wait();
  return ok;
}

// 8: one clean and one tainted writer share the pipe.
static int
t_pipe_shared(void)
{
  int p[2], ok;
  char buf[8];

  if(pipe(p) < 0)
    return 0;
  if(fork() == 0){
    close(p[0]);
    write(p[1], "c", 1);
    exit();
  }
  if(fork() == 0){
    close(p[0]);
    readfile(UNTR);
    write(p[1], "t", 1);
    exit();
  }
  close(p[1]);
  ok = istainted() == 0;
  while(read(p[0], buf, sizeof(buf)) > 0)
    ;
  close(p[0]);
  wait();
  wait();
  return ok && istainted() == 1;
}

// 9
static int
t_unlink_refused(void)
{
  if(readfile(UNTR) <= 0 || istainted() != 1)
    return 0;
  return unlink(VICTIM) == -1 && exists(VICTIM);
}

// 10
static int
t_unlink_clean(void)
{
  touch("tt.tmp");
  return istainted() == 0 && unlink("tt.tmp") == 0 && !exists("tt.tmp");
}

// 11
static int
t_dup(void)
{
  int fd, fd2;
  char c;

  if((fd = open(UNTR, O_RDONLY)) < 0)
    return 0;
  fd2 = dup(fd);
  close(fd);
  if(istainted() != 0)
    return 0;
  return read(fd2, &c, 1) == 1 && istainted() == 1;
}

// 12: runs in the parent and only uses fstat, so it cannot taint it.
static void
t_persist(int num)
{
  if(!exists(PERSIST)){
    mkfile(PERSIST, "persist\n");
    marktaint(PERSIST);
    printf(1, "%d SKIP flag persists across reboot "
           "(marked %s; reboot from the same fs.img and run tainttest again)\n",
           num, PERSIST);
    return;
  }
  report(num, "flag persists across reboot", untrusted(PERSIST) == 1);
}

// 13: a deleted-then-recreated file reuses the freed inode and must
// not inherit its untrusted flag.
static int
t_recreate(void)
{
  int ok;

  mkfile("tt.re", "old\n");
  marktaint("tt.re");
  ok = untrusted("tt.re") == 1;
  mkfile("tt.re", "new\n");   // unlink + create
  ok = ok && untrusted("tt.re") == 0 && readfile("tt.re") > 0;
  return ok && istainted() == 0;
}

// 14: tt.w is created while clean, then written after taint. The
// write itself must mark it (create can't have: it was clean then).
static int
t_write_marks(void)
{
  int fd, ok;

  if((fd = open("tt.w", O_CREATE | O_RDWR)) < 0)
    return 0;
  ok = untrusted("tt.w") == 0;
  ok = ok && readfile(UNTR) > 0 && istainted() == 1;
  ok = ok && write(fd, "x", 1) == 1;
  close(fd);
  return ok && untrusted("tt.w") == 1;
}

// 15: only creating a file (no write) while tainted.
static int
t_create_marks(void)
{
  if(readfile(UNTR) <= 0)
    return 0;
  touch("tt.c");
  return untrusted("tt.c") == 1;
}

// 16: a clean process's files stay clean.
static int
t_clean_write(void)
{
  mkfile("tt.w", "clean\n");
  return untrusted("tt.w") == 0 && istainted() == 0;
}

// 17: write-down. CLEAN already holds data, so the write is refused
// and the content is unchanged.
static int
t_writedown(void)
{
  char buf[32];
  int fd, n, ok;

  if(readfile(UNTR) <= 0 || (fd = open(CLEAN, O_RDWR)) < 0)
    return 0;
  ok = write(fd, "INJECTED", 8) == -1;
  close(fd);
  if((fd = open(CLEAN, O_RDONLY)) < 0)
    return 0;
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  buf[n > 0 ? n : 0] = 0;
  return ok && strcmp(buf, "clean data\n") == 0;
}

// 18: a tainted process may write to its own (untrusted) files.
static int
t_write_own(void)
{
  int fd, ok;

  if(readfile(UNTR) <= 0 || (fd = open("tt.c", O_CREATE | O_RDWR)) < 0)
    return 0;
  ok = write(fd, "mine\n", 5) == 5;
  close(fd);
  return ok && untrusted("tt.c") == 1;
}

// 19: the console is a device, not a clean file.
static int
t_console(void)
{
  if(readfile(UNTR) <= 0)
    return 0;
  return write(1, "   (tainted console write)\n", 27) == 27;
}

// 20: a tainted process may not run a program outside /safe. If exec
// succeeded we would become ls and never create tt.ok.
static int
t_exec_outside(void)
{
  char *argv[] = { "ls", 0 };

  if(readfile(UNTR) <= 0)
    return 0;
  return exec("/ls", argv) == -1;
}

// 21: /safe is checked by inode, so ".." can't escape it.
static int
t_exec_dotdot(void)
{
  char *argv[] = { "ls", 0 };

  if(readfile(UNTR) <= 0)
    return 0;
  return exec("/safe/../ls", argv) == -1;
}

// 22: a tainted process may not link anything into /safe.
static int
t_link_tainted(void)
{
  if(readfile(UNTR) <= 0)
    return 0;
  return link(CLEAN, "/safe/tt.l") == -1 && !exists("/safe/tt.l");
}

// 23: even a clean process may not link an untrusted file into /safe.
static int
t_link_untrusted(void)
{
  return link(UNTR, "/safe/tt.l") == -1 && !exists("/safe/tt.l") &&
         istainted() == 0;
}

// 24: a tainted process may not create a file in /safe.
static int
t_create_safe(void)
{
  if(readfile(UNTR) <= 0)
    return 0;
  return open("/safe/tt.l", O_CREATE | O_RDWR) < 0 && !exists("/safe/tt.l");
}

// 25: copy /echo to tt.bin while clean, mark the copy untrusted, run
// it: the exec taints us and, since tt.bin is not in /safe, fails.
static int
t_exec_untrusted(void)
{
  char buf[512], *argv[] = { "tt.bin", 0 };
  int in, out, n;

  if((in = open("/echo", O_RDONLY)) < 0 ||
     (out = open("tt.bin", O_CREATE | O_RDWR)) < 0)
    return 0;
  while((n = read(in, buf, sizeof(buf))) > 0)
    write(out, buf, n);
  close(in);
  close(out);
  if(marktaint("tt.bin") < 0 || istainted() != 0)
    return 0;
  return exec("tt.bin", argv) == -1 && istainted() == 1;
}

// 26: a clean writer writes "c", then a tainted writer writes "t", and
// we read only the first byte. Per-byte tracking keeps us clean;
// per-pipe tracking taints us (the known false positive). Reading the
// tainted byte must taint in both modes.
static int
t_pipe_cleanpart(void)
{
  int p[2], ok, first;
  char c;

  if(pipe(p) < 0)
    return 0;
  if(fork() == 0){
    close(p[0]);
    write(p[1], "c", 1);
    exit();
  }
  wait();
  if(fork() == 0){
    close(p[0]);
    readfile(UNTR);
    write(p[1], "t", 1);
    exit();
  }
  wait();
  close(p[1]);
  ok = read(p[0], &c, 1) == 1 && c == 'c';
  first = istainted();
  printf(1, "   after reading only the clean byte: tainted=%d\n", first);
  ok = ok && first == !PIPE_PERBYTE;
  ok = ok && read(p[0], &c, 1) == 1 && c == 't' && istainted() == 1;
  close(p[0]);
  return ok;
}

// 27: a tainted writer sends more than the 512-byte buffer, so it
// sleeps half way. The bytes already in the pipe must taint.
static int
t_pipe_bigwrite(void)
{
  int p[2], ok;
  char buf[100];

  if(pipe(p) < 0)
    return 0;
  if(fork() == 0){
    char big[1000];

    close(p[0]);
    memset(big, 'x', sizeof(big));
    readfile(UNTR);
    write(p[1], big, sizeof(big));
    exit();
  }
  close(p[1]);
  ok = read(p[0], buf, 1) == 1 && istainted() == 1;
  while(read(p[0], buf, sizeof(buf)) > 0)
    ;
  close(p[0]);
  wait();
  return ok;
}

int
main(int argc, char *argv[])
{
  if(argc == 2 && strcmp(argv[1], "-exec-child") == 0){
    if(istainted() == 1)
      touch(OKFILE);
    exit();
  }

  printf(1, "tainttest: pipe taint mode %s\n", PIPE_PERBYTE ? "per-byte" : "per-pipe");
  mkfile(CLEAN, "clean data\n");
  mkfile(UNTR, "untrusted data\n");
  marktaint(UNTR);
  mkfile(VICTIM, "victim\n");

  run(1, "fresh process is not tainted", t_fresh);
  run(2, "reading a clean file does not taint", t_read_clean);
  run(3, "reading an untrusted file taints", t_read_untrusted);
  run(4, "opening an untrusted file without reading does not taint", t_open_only);
  run(5, "child forked after taint is tainted, child forked before is not", t_fork);
  run(6, "taint survives exec (of /safe/tainttest)", t_exec);
  run(7, "pipe: tainted writer taints the clean reader", t_pipe);
  run(8, "pipe shared by clean and tainted writers taints the reader", t_pipe_shared);
  run(9, "tainted unlink returns -1 and the file still exists", t_unlink_refused);
  run(10, "clean process can still unlink", t_unlink_clean);
  run(11, "reading through a dup'd fd taints", t_dup);
  t_persist(12);
  run(13, "deleted-then-recreated file starts clean", t_recreate);
  run(14, "tainted write to an empty clean file marks it untrusted", t_write_marks);
  run(15, "file created by a tainted process starts untrusted", t_create_marks);
  run(16, "files written by a clean process stay clean", t_clean_write);
  run(17, "write-down: tainted write to a clean file is refused", t_writedown);
  run(18, "tainted process can write its own untrusted file", t_write_own);
  run(19, "tainted process can still write to the console", t_console);
  run(20, "tainted exec outside /safe is refused", t_exec_outside);
  run(21, "tainted exec of /safe/../ls is refused", t_exec_dotdot);
  run(22, "tainted link into /safe is refused", t_link_tainted);
  run(23, "linking an untrusted file into /safe is refused", t_link_untrusted);
  run(24, "tainted create in /safe is refused", t_create_safe);
  run(25, "running an untrusted program taints, and is refused", t_exec_untrusted);
  run(26, PIPE_PERBYTE ? "pipe: reading only clean bytes does not taint (per-byte)"
                       : "pipe: reading only clean bytes taints (per-pipe false positive)",
      t_pipe_cleanpart);
  run(27, "pipe: a writer sleeping mid-write has already tainted its bytes", t_pipe_bigwrite);

  report(0, "parent stayed clean", istainted() == 0);
  if(fails)
    printf(1, "tainttest: %d FAILED\n", fails);
  else
    printf(1, "tainttest: ALL PASSED\n");
  exit();
}
