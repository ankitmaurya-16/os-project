// agentd: guest-side request server for the host AI agent.
//
// One agentd process serves a whole agent session. That is the point:
// once it reads untrusted data the kernel taints it, and every later
// request in the session (e.g. DELETE) runs as a tainted process. If
// each tool call were a separate shell command, the shell would fork a
// fresh, clean process for each one and the kernel would never refuse.
//
// Requests, one per line, with an optional leading id:
//     [<id>] LS
//     [<id>] READ <path>
//     [<id>] DELETE <path>
//     [<id>] STATUS
// The host bridge always sends a random id, so file content printed by
// READ cannot forge the end marker. Without an id, a counter is used.
//
// Every request gets exactly one framed reply:
//     @@BEGIN <id>
//     ...output...
//     @@END <id> <OK|ERR> tainted=<0|1>
//
// Everything is done with system calls directly: no exec, no shell.
//
// "agentd -u" talks over /uart1 (the second serial port) instead of
// the console, so kernel messages and agent replies use separate wires.

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"

#define MAXLINE 128
#define MAXTOK  4
#define MAXID   16

static int
isverb(char *s)
{
  return strcmp(s, "LS") == 0 || strcmp(s, "READ") == 0 ||
         strcmp(s, "DELETE") == 0 || strcmp(s, "STATUS") == 0;
}

static int
validid(char *s)
{
  int n = strlen(s);

  if(n == 0 || n > MAXID)
    return 0;
  for(; *s; s++)
    if(!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
         (*s >= '0' && *s <= '9')))
      return 0;
  return 1;
}

// Paths: at most DIRSIZ chars from [A-Za-z0-9/._-], and no "..".
static int
validpath(char *path)
{
  char *s;
  int n = strlen(path);

  if(n == 0 || n > DIRSIZ)
    return 0;
  for(s = path; *s; s++){
    if(!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
         (*s >= '0' && *s <= '9') || *s == '/' || *s == '.' ||
         *s == '_' || *s == '-'))
      return 0;
    if(s[0] == '.' && s[1] == '.')
      return 0;
  }
  return 1;
}

// One line per entry of /: name type size untrusted.
static int
do_ls(void)
{
  int dfd, fd;
  struct dirent de;
  struct stat st;
  char path[DIRSIZ+2];

  if((dfd = open("/", O_RDONLY)) < 0){
    printf(1, "error: cannot open /\n");
    return -1;
  }
  while(read(dfd, &de, sizeof(de)) == sizeof(de)){
    if(de.inum == 0)
      continue;
    path[0] = '/';
    memmove(path+1, de.name, DIRSIZ);
    path[DIRSIZ+1] = 0;
    if(strcmp(path, "/.") == 0 || strcmp(path, "/..") == 0)
      continue;
    if((fd = open(path, O_RDONLY)) < 0)
      continue;
    fstat(fd, &st);   // fstat only: listing never taints
    close(fd);
    printf(1, "%s %d %d %d\n", path+1, st.type, st.size, st.untrusted);
  }
  close(dfd);
  return 0;
}

static int
do_read(char *path)
{
  int fd, n;
  char buf[512], last = '\n';

  if((fd = open(path, O_RDONLY)) < 0){
    printf(1, "error: cannot open %s\n", path);
    return -1;
  }
  while((n = read(fd, buf, sizeof(buf))) > 0){
    write(1, buf, n);
    last = buf[n-1];
  }
  close(fd);
  if(last != '\n')
    printf(1, "\n");   // keep the end marker on its own line
  if(n < 0){
    printf(1, "error: read failed\n");
    return -1;
  }
  return 0;
}

static int
do_delete(char *path)
{
  if(unlink(path) < 0){
    printf(1, "error: unlink %s refused or failed\n", path);
    return -1;
  }
  printf(1, "deleted %s\n", path);
  return 0;
}

// Write the decimal form of v (v >= 0) into buf.
static void
itoa(int v, char *buf)
{
  char tmp[12];
  int i = 0;

  do {
    tmp[i++] = '0' + v % 10;
    v /= 10;
  } while(v);
  while(i > 0)
    *buf++ = tmp[--i];
  *buf = 0;
}

// Split s in place on whitespace. Returns the token count, or -1 if
// there are more than max tokens.
static int
split(char *s, char **tok, int max)
{
  int n = 0;

  while(*s){
    while(*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
      *s++ = 0;
    if(*s == 0)
      break;
    if(n == max)
      return -1;
    tok[n++] = s;
    while(*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
      s++;
  }
  return n;
}

// Run one request (verb plus its arguments). Returns 0 or -1.
static int
dispatch(int argc, char **argv)
{
  char *verb = argv[0];

  if(strcmp(verb, "LS") == 0 && argc == 1)
    return do_ls();
  if(strcmp(verb, "STATUS") == 0 && argc == 1){
    printf(1, "tainted=%d\n", istainted());
    return 0;
  }
  if((strcmp(verb, "READ") == 0 || strcmp(verb, "DELETE") == 0) && argc == 2){
    if(!validpath(argv[1])){
      printf(1, "error: bad path\n");
      return -1;
    }
    return verb[0] == 'R' ? do_read(argv[1]) : do_delete(argv[1]);
  }
  printf(1, "error: malformed request\n");
  return -1;
}

int
main(int argc, char *argv[])
{
  char line[MAXLINE], idbuf[12];
  char *tok[MAXTOK], *id, **req;
  int n, nreq, rc, seq;

  if(argc == 2 && strcmp(argv[1], "-u") == 0){
    // Same trick as init uses for the console: the lowest free fd is
    // reused, so this makes fd 0 and fd 1 the agent line.
    close(0);
    if(open("/uart1", O_RDWR) != 0){
      printf(2, "agentd: cannot open /uart1\n");
      exit();
    }
    close(1);
    dup(0);
    printf(2, "agentd: serving on /uart1\n");
  }

  printf(1, "@@READY\n");
  for(seq = 1; ; seq++){
    memset(line, 0, sizeof(line));
    gets(line, sizeof(line));
    if(line[0] == 0)          // end of input (Ctrl-D)
      break;
    if((n = split(line, tok, MAXTOK)) == 0)
      continue;

    // Optional leading id.
    req = tok;
    nreq = n;
    id = "-";
    if(n > 0 && isverb(tok[0])){
      itoa(seq, idbuf);       // no id given: use the sequence number
      id = idbuf;
    } else if(n > 1 && validid(tok[0])){
      id = tok[0];
      req = tok + 1;
      nreq = n - 1;
    } else {
      nreq = 0;               // malformed: no usable verb
    }

    printf(1, "@@BEGIN %s\n", id);
    if(nreq > 0)
      rc = dispatch(nreq, req);
    else {
      printf(1, "error: malformed request\n");
      rc = -1;
    }
    printf(1, "@@END %s %s tainted=%d\n", id, rc == 0 ? "OK" : "ERR", istainted());
  }
  exit();
}
