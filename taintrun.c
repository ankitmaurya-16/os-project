// taintrun: run a program as a tainted process.
//
//   marktaint /inbox.txt
//   taintrun /safe/ls
//
// Reads /inbox.txt (which must be marked untrusted) so that this
// process is tainted, then execs the program. Used to build the
// false-positive table: what still works under the policy.

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

int
main(int argc, char *argv[])
{
  char buf[128];
  int fd;

  if(argc < 2){
    printf(2, "usage: taintrun prog [args...]\n");
    exit();
  }
  if((fd = open("/inbox.txt", O_RDONLY)) >= 0){
    while(read(fd, buf, sizeof(buf)) > 0)
      ;
    close(fd);
  }
  if(!istainted()){
    printf(2, "taintrun: not tainted (run marktaint /inbox.txt first)\n");
    exit();
  }
  exec(argv[1], argv + 1);
  printf(2, "taintrun: exec %s failed\n", argv[1]);
  exit();
}
