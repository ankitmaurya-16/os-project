// helper: demo for taint crossing a pipe.
//
//   marktaint /inbox.txt ; cat /inbox.txt | helper /important.txt
//
// Reads stdin to EOF, reports whether it is now tainted, then tries to
// unlink the path given as argv[1] and reports the result.

#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  char buf[128];
  int n, total;

  if(argc != 2){
    printf(2, "usage: helper path\n");
    exit();
  }
  total = 0;
  while((n = read(0, buf, sizeof(buf))) > 0)
    total += n;
  printf(1, "helper: read %d bytes, tainted=%d\n", total, istainted());
  printf(1, "helper: unlink(%s) = %d\n", argv[1], unlink(argv[1]));
  exit();
}
