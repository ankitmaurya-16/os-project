// persisttest: check that the untrusted flag is stored on disk.
//
//   persisttest mark    create pt.file, check it starts clean,
//                       mark it untrusted and check the flag
//   (quit QEMU, boot again from the same fs.img)
//   persisttest check   check pt.file is still untrusted
//
// It only uses fstat(), never read(), so the test itself never
// becomes tainted.

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

#define FILE "pt.file"

static int fails;

static void
check(char *what, int ok)
{
  printf(1, "persisttest: %s: %s\n", what, ok ? "PASS" : "FAIL");
  if(!ok)
    fails++;
}

// Returns the file's untrusted flag, or -1 if it cannot be opened.
static int
flag(char *path)
{
  int fd;
  struct stat st;

  if((fd = open(path, O_RDONLY)) < 0)
    return -1;
  fstat(fd, &st);
  close(fd);
  return st.untrusted;
}

static void
mark(void)
{
  int fd;

  unlink(FILE);
  if((fd = open(FILE, O_CREATE | O_RDWR)) < 0){
    printf(1, "persisttest: cannot create %s\n", FILE);
    exit();
  }
  write(fd, "secret\n", 7);
  close(fd);
  check("new file starts trusted", flag(FILE) == 0);
  check("marktaint returns 0", marktaint(FILE) == 0);
  check("flag is set after marktaint", flag(FILE) == 1);
  check("marktaint on missing path returns -1", marktaint("no.such.file") == -1);
  check("marking did not taint this process", istainted() == 0);
}

int
main(int argc, char *argv[])
{
  if(argc == 2 && strcmp(argv[1], "mark") == 0)
    mark();
  else if(argc == 2 && strcmp(argv[1], "check") == 0)
    check("flag survived reboot", flag(FILE) == 1);
  else {
    printf(2, "usage: persisttest mark|check\n");
    exit();
  }
  printf(1, "persisttest: %s\n", fails ? "SOME TESTS FAILED" : "ALL PASSED");
  exit();
}
