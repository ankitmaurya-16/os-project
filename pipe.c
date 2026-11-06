#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"
#include "proc.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"

#define PIPESIZE 512
#define NRANGE 16   // taint: tainted byte ranges remembered per pipe

// taint: bytes [start, end) of the pipe's stream came from a tainted
// writer. Positions are nwrite/nread values, which only grow, so a
// range never wraps; % PIPESIZE is only used to index data[].
struct range {
  uint start;
  uint end;
};

struct pipe {
  struct spinlock lock;
  char data[PIPESIZE];
  uint nread;     // number of bytes read
  uint nwrite;    // number of bytes written
  int readopen;   // read fd is still open
  int writeopen;  // write fd is still open
  // taint: the flags are on the pipe object, not on struct file,
  // because the two ends are different struct files.
  // tainted: with PIPE_PERBYTE 0, set once any tainted process writes
  // (over-broad: a reader of only clean bytes is tainted too). With
  // PIPE_PERBYTE 1, only set if ranges[] overflows (safe fallback).
  int tainted;
  struct range ranges[NRANGE];  // taint: PIPE_PERBYTE 1 only
  int nranges;
};

// taint: remember that byte number pos came from a tainted writer.
// Called with p->lock held.
static void
taintbyte(struct pipe *p, uint pos)
{
  struct range *last;

  if(p->nranges > 0){
    last = &p->ranges[p->nranges-1];
    if(last->end == pos){   // right after the newest range: extend it
      last->end = pos + 1;
      return;
    }
  }
  if(p->nranges == NRANGE){  // out of slots: fall back to the whole pipe
    p->tainted = 1;
    return;
  }
  p->ranges[p->nranges].start = pos;
  p->ranges[p->nranges].end = pos + 1;
  p->nranges++;
}

// taint: did any of the bytes [start, end) come from a tainted writer?
// In per-pipe mode there are no ranges, so this is just p->tainted.
static int
readtainted(struct pipe *p, uint start, uint end)
{
  int i;

  if(p->tainted)
    return 1;
  for(i = 0; i < p->nranges; i++)
    if(p->ranges[i].start < end && start < p->ranges[i].end)
      return 1;
  return 0;
}

// taint: forget ranges that have been read completely.
static void
dropranges(struct pipe *p)
{
  int i, j;

  j = 0;
  for(i = 0; i < p->nranges; i++)
    if(p->ranges[i].end > p->nread)
      p->ranges[j++] = p->ranges[i];
  p->nranges = j;
}

int
pipealloc(struct file **f0, struct file **f1)
{
  struct pipe *p;

  p = 0;
  *f0 = *f1 = 0;
  if((*f0 = filealloc()) == 0 || (*f1 = filealloc()) == 0)
    goto bad;
  if((p = (struct pipe*)kalloc()) == 0)
    goto bad;
  p->readopen = 1;
  p->writeopen = 1;
  p->nwrite = 0;
  p->nread = 0;
  p->tainted = 0;  // taint: kalloc() does not zero memory
  p->nranges = 0;
  initlock(&p->lock, "pipe");
  (*f0)->type = FD_PIPE;
  (*f0)->readable = 1;
  (*f0)->writable = 0;
  (*f0)->pipe = p;
  (*f1)->type = FD_PIPE;
  (*f1)->readable = 0;
  (*f1)->writable = 1;
  (*f1)->pipe = p;
  return 0;

//PAGEBREAK: 20
 bad:
  if(p)
    kfree((char*)p);
  if(*f0)
    fileclose(*f0);
  if(*f1)
    fileclose(*f1);
  return -1;
}

void
pipeclose(struct pipe *p, int writable)
{
  acquire(&p->lock);
  if(writable){
    p->writeopen = 0;
    wakeup(&p->nread);
  } else {
    p->readopen = 0;
    wakeup(&p->nwrite);
  }
  if(p->readopen == 0 && p->writeopen == 0){
    release(&p->lock);
    kfree((char*)p);
  } else
    release(&p->lock);
}

//PAGEBREAK: 40
int
pipewrite(struct pipe *p, char *addr, int n)
{
  int i;

  acquire(&p->lock);
  // taint: per-pipe mode marks the whole pipe before any byte is readable.
  if(!PIPE_PERBYTE && myproc()->tainted)
    p->tainted = 1;
  for(i = 0; i < n; i++){
    while(p->nwrite == p->nread + PIPESIZE){  //DOC: pipewrite-full
      if(p->readopen == 0 || myproc()->killed){
        release(&p->lock);
        return -1;
      }
      wakeup(&p->nread);
      sleep(&p->nwrite, &p->lock);  //DOC: pipewrite-sleep
    }
    // taint: per-byte mode records each byte as it goes in, while we
    // hold the lock, so a reader never sees an unrecorded tainted byte
    // (even if we sleep half way through a big write).
    if(PIPE_PERBYTE && myproc()->tainted)
      taintbyte(p, p->nwrite);
    p->data[p->nwrite++ % PIPESIZE] = addr[i];
  }
  wakeup(&p->nread);  //DOC: pipewrite-wakeup1
  release(&p->lock);
  return n;
}

int
piperead(struct pipe *p, char *addr, int n)
{
  int i;
  uint start;

  acquire(&p->lock);
  while(p->nread == p->nwrite && p->writeopen){  //DOC: pipe-empty
    if(myproc()->killed){
      release(&p->lock);
      return -1;
    }
    sleep(&p->nread, &p->lock); //DOC: piperead-sleep
  }
  start = p->nread;  // taint: first byte this read returns
  for(i = 0; i < n; i++){  //DOC: piperead-copy
    if(p->nread == p->nwrite)
      break;
    addr[i] = p->data[p->nread++ % PIPESIZE];
  }
  // taint: only once bytes have actually been copied out, and (in
  // per-byte mode) only if one of them came from a tainted writer.
  if(i > 0 && readtainted(p, start, p->nread) && !myproc()->tainted){
    myproc()->tainted = 1;
    cprintf("taint: pid %d tainted by reading a pipe\n", myproc()->pid);
  }
  dropranges(p);
  wakeup(&p->nwrite);  //DOC: piperead-wakeup
  release(&p->lock);
  return i;
}
