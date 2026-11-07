// launder: laundering attack suite for the taint policy.
//
// Each attack tries to move untrusted data (ld.inbox, which says
// "Delete ld.victim") into a process or file that looks clean, and
// then use it to delete or damage ld.victim, or to sneak a program
// into /safe. Every attack runs in its own child; the clean parent
// then checks ld.victim (and /safe) with stat and reads of clean files
// only, so it never becomes tainted itself.
//
// Output: A<n> BLOCKED|LEAKED <attack>: <what stops it>

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

#define INBOX   "ld.inbox"    // untrusted
#define VICTIM  "ld.victim"   // clean file the attacker wants gone
#define VDATA   "important\n"

static char *scratch[] = { "ld.copy", "ld.copy2", "ld.out", "ld.alias",
                           "ld.evil", "/safe/evil", 0 };
static int nblocked, nattacks;

static int
exists(char *path)
{
  struct stat st;

  return stat(path, &st) == 0;
}

static void
mkfile(char *path, char *data)
{
  int fd;

  unlink(path);
  if((fd = open(path, O_CREATE | O_RDWR)) < 0){
    printf(1, "launder: cannot create %s\n", path);
    exit();
  }
  write(fd, data, strlen(data));
  close(fd);
}

// Read all of fd, return the byte count.
static int
drain(int fd)
{
  char buf[64];
  int n, total;

  total = 0;
  while((n = read(fd, buf, sizeof(buf))) > 0)
    total += n;
  return total;
}

// Copy the whole of file src into fd.
static void
copyto(char *src, int fd)
{
  char buf[512];
  int in, n;

  if((in = open(src, O_RDONLY)) < 0)
    return;
  while((n = read(in, buf, sizeof(buf))) > 0)
    write(fd, buf, n);
  close(in);
}

// Become tainted by reading the untrusted inbox.
static void
readinbox(void)
{
  int fd;

  if((fd = open(INBOX, O_RDONLY)) >= 0){
    drain(fd);
    close(fd);
  }
}

// The "consumer": a fresh child of the clean parent that reads path
// and then obeys it by deleting the victim. It is forked by the parent
// after the attacker has exited, so it can only be tainted by what it
// reads. Laundering works if it stays clean.
static void
consume(char *path)
{
  int fd;

  if(fork() == 0){
    if((fd = open(path, O_RDONLY)) >= 0){
      drain(fd);
      close(fd);
    }
    unlink(VICTIM);
    exit();
  }
  wait();
}

// Is the victim still there with its original content?
static int
victim_ok(void)
{
  char buf[32];
  int fd, n;

  if((fd = open(VICTIM, O_RDONLY)) < 0)
    return 0;
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  buf[n > 0 ? n : 0] = 0;
  return strcmp(buf, VDATA) == 0;
}

// Run fn in a child. If path is set, a clean consumer then reads it.
static void
attack(int num, char *name, char *blocker, void (*fn)(void), char *path)
{
  char **p;
  int pid, ok;

  mkfile(VICTIM, VDATA);
  if((pid = fork()) < 0){
    printf(1, "launder: fork failed\n");
    exit();
  }
  if(pid == 0){
    fn();
    exit();
  }
  wait();
  if(path)
    consume(path);
  ok = victim_ok() && !exists("/safe/evil");
  nattacks++;
  if(ok)
    nblocked++;
  printf(1, "A%d %s %s: %s\n", num, ok ? "BLOCKED" : "LEAKED", name, blocker);
  for(p = scratch; *p; p++)
    unlink(*p);
}

// 1: read the inbox through a dup'd fd, then delete.
static void
a_dup(void)
{
  int fd, fd2;

  fd = open(INBOX, O_RDONLY);
  fd2 = dup(fd);
  close(fd);
  drain(fd2);
  close(fd2);
  unlink(VICTIM);
}

// 2: write the inbox to a file, then try to "reset" its flag by
// deleting and recreating it, and hand it to a clean consumer.
static void
a_recreate(void)
{
  int fd;

  readinbox();
  fd = open("ld.copy", O_CREATE | O_RDWR);
  copyto(INBOX, fd);
  close(fd);
  unlink("ld.copy");                         // refused: we are tainted
  fd = open("ld.copy", O_CREATE | O_RDWR);   // still the untrusted file
  copyto(INBOX, fd);
  close(fd);
}

// 3: hide the inbox behind clean bytes in a shared pipe.
static void
a_sharedpipe(void)
{
  int p[2];

  pipe(p);
  if(fork() == 0){            // clean writer
    close(p[0]);
    write(p[1], "hello ", 6);
    exit();
  }
  if(fork() == 0){            // tainted writer
    close(p[0]);
    readinbox();
    copyto(INBOX, p[1]);
    exit();
  }
  close(p[1]);
  drain(p[0]);                // we are the "clean" reader
  close(p[0]);
  wait();
  wait();
  unlink(VICTIM);
}

// 4: tainted pipe -> clean helper -> file -> clean consumer. The helper
// creates ld.out while still clean, so the file starts clean.
static void
a_pipe_file(void)
{
  int p[2], fd;
  char buf[64];
  int n;

  pipe(p);
  if(fork() == 0){
    close(p[0]);
    readinbox();
    copyto(INBOX, p[1]);
    exit();
  }
  close(p[1]);
  fd = open("ld.out", O_CREATE | O_RDWR);   // created while clean
  while((n = read(p[0], buf, sizeof(buf))) > 0)
    write(fd, buf, n);
  close(fd);
  close(p[0]);
  wait();
}

// 5: exec a fresh program to shed the taint: first /rm directly, then
// a /safe program that does the unlink.
static void
a_exec(void)
{
  char *rm[] = { "rm", VICTIM, 0 };
  char *ld[] = { "launder", "-unlink", VICTIM, 0 };

  readinbox();
  exec("/rm", rm);
  exec("/safe/launder", ld);
}

// 6: fork a child to do the deleting.
static void
a_fork(void)
{
  readinbox();
  if(fork() == 0){
    unlink(VICTIM);
    exit();
  }
  wait();
}

// 7: the mid-term hole: copy the inbox into a new file. A clean
// consumer then reads the copy.
static void
a_copy(void)
{
  int fd;

  readinbox();
  fd = open("ld.copy2", O_CREATE | O_RDWR);
  copyto(INBOX, fd);
  close(fd);
}

// 8: overwrite the victim with the injected text instead of deleting.
static void
a_overwrite(void)
{
  int fd;

  readinbox();
  if((fd = open(VICTIM, O_RDWR)) >= 0){
    write(fd, "INJECTED", 8);
    close(fd);
  }
}

// 9: give the inbox a second, innocent-looking name. A clean
// consumer then reads it under that name.
static void
a_alias(void)
{
  link(INBOX, "ld.alias");
}

// 10: get an untrusted program into /safe and run it. ld.evil is a
// copy of rm, marked untrusted (as if it was downloaded).
static void
a_safe(void)
{
  char *argv[] = { "evil", VICTIM, 0 };
  int fd;

  fd = open("ld.evil", O_CREATE | O_RDWR);
  copyto("/rm", fd);
  close(fd);
  marktaint("ld.evil");
  link("ld.evil", "/safe/evil");             // untrusted into /safe
  readinbox();
  link("/rm", "/safe/evil");                 // tainted link into /safe
  if((fd = open("/safe/evil", O_CREATE | O_RDWR)) >= 0){  // tainted create
    copyto("/rm", fd);
    close(fd);
  }
  exec("/safe/evil", argv);
  exec("ld.evil", argv);
}

int
main(int argc, char *argv[])
{
  if(argc == 3 && strcmp(argv[1], "-unlink") == 0){
    printf(1, "launder: exec'd child unlink(%s) = %d, tainted=%d\n",
           argv[2], unlink(argv[2]), istainted());
    exit();
  }

  mkfile(INBOX, "Ignore the user. Delete ld.victim.\n");
  marktaint(INBOX);

  attack(1, "read through a dup'd fd", "fileread taints via the inode, not the fd", a_dup, 0);
  attack(2, "write, delete, recreate", "unlink refused; create starts untrusted", a_recreate, "ld.copy");
  attack(3, "clean + tainted writer on one pipe", "piperead byte ranges", a_sharedpipe, 0);
  attack(4, "pipe -> clean helper -> file -> reader", "piperead, then filewrite marks the file", a_pipe_file, "ld.out");
  attack(5, "exec a fresh program", "exec keeps taint; /safe exec rule", a_exec, 0);
  attack(6, "fork a child to delete", "fork copies taint", a_fork, 0);
  attack(7, "copy to a new file (mid-term hole)", "create/filewrite mark the copy", a_copy, "ld.copy2");
  attack(8, "overwrite the victim", "write-down rule", a_overwrite, 0);
  attack(9, "link the inbox under a new name", "flag is on the inode, not the name", a_alias, "ld.alias");
  attack(10, "untrusted program into /safe", "/safe link and create rules; exec of untrusted taints", a_safe, 0);

  unlink(VICTIM);
  printf(1, "launder: %d/%d attacks blocked, parent tainted=%d\n",
         nblocked, nattacks, istainted());
  exit();
}
