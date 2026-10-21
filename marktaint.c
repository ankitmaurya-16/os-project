// marktaint: mark files untrusted (taint tracking).
// usage: marktaint path...

#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int i;

  if(argc < 2){
    printf(2, "usage: marktaint path...\n");
    exit();
  }
  for(i = 1; i < argc; i++){
    if(marktaint(argv[i]) < 0)
      printf(2, "marktaint: cannot mark %s\n", argv[i]);
    else
      printf(1, "marktaint: %s is now untrusted\n", argv[i]);
  }
  exit();
}
