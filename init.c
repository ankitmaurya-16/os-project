// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

char *argv[] = { "sh", 0 };

// taint: trusted programs that a tainted process may still run.
char *safeprogs[] = { "cat", "echo", "grep", "wc", "ls", "sh", "helper",
                      "tainttest", "launder", "taintrun", 0 };

// taint: build /safe at boot by hard-linking the trusted programs.
// Errors (already there after a reboot, program missing) are ignored.
static void
mksafe(void)
{
  char src[32], dst[32];
  int i;

  mkdir("/safe");
  for(i = 0; safeprogs[i]; i++){
    strcpy(src, "/");
    strcpy(src + 1, safeprogs[i]);
    strcpy(dst, "/safe/");
    strcpy(dst + 6, safeprogs[i]);
    link(src, dst);
  }
}

int
main(void)
{
  int pid, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr
  mksafe();  // taint
  mknod("uart1", 2, 0);  // taint: agent line (UART1); fails if it exists

  for(;;){
    printf(1, "init: starting sh\n");
    pid = fork();
    if(pid < 0){
      printf(1, "init: fork failed\n");
      exit();
    }
    if(pid == 0){
      exec("sh", argv);
      printf(1, "init: exec sh failed\n");
      exit();
    }
    while((wpid=wait()) >= 0 && wpid != pid)
      printf(1, "zombie!\n");
  }
}
