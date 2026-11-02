//
// File descriptors
//

#include "types.h"
#include "defs.h"
#include "param.h"
#include "mmu.h"   // taint: for struct proc
#include "proc.h"  // taint: for myproc()->tainted
#include "stat.h"  // taint: for T_FILE
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"

struct devsw devsw[NDEV];
struct {
  struct spinlock lock;
  struct file file[NFILE];
} ftable;

void
fileinit(void)
{
  initlock(&ftable.lock, "ftable");
}

// Allocate a file structure.
struct file*
filealloc(void)
{
  struct file *f;

  acquire(&ftable.lock);
  for(f = ftable.file; f < ftable.file + NFILE; f++){
    if(f->ref == 0){
      f->ref = 1;
      release(&ftable.lock);
      return f;
    }
  }
  release(&ftable.lock);
  return 0;
}

// Increment ref count for file f.
struct file*
filedup(struct file *f)
{
  acquire(&ftable.lock);
  if(f->ref < 1)
    panic("filedup");
  f->ref++;
  release(&ftable.lock);
  return f;
}

// Close file f.  (Decrement ref count, close when reaches 0.)
void
fileclose(struct file *f)
{
  struct file ff;

  acquire(&ftable.lock);
  if(f->ref < 1)
    panic("fileclose");
  if(--f->ref > 0){
    release(&ftable.lock);
    return;
  }
  ff = *f;
  f->ref = 0;
  f->type = FD_NONE;
  release(&ftable.lock);

  if(ff.type == FD_PIPE)
    pipeclose(ff.pipe, ff.writable);
  else if(ff.type == FD_INODE){
    begin_op();
    iput(ff.ip);
    end_op();
  }
}

// Get metadata about file f.
int
filestat(struct file *f, struct stat *st)
{
  if(f->type == FD_INODE){
    ilock(f->ip);
    stati(f->ip, st);
    iunlock(f->ip);
    return 0;
  }
  return -1;
}

// Read from file f.
int
fileread(struct file *f, char *addr, int n)
{
  int r;

  if(f->readable == 0)
    return -1;
  if(f->type == FD_PIPE)
    return piperead(f->pipe, addr, n);
  if(f->type == FD_INODE){
    ilock(f->ip);
    if((r = readi(f->ip, addr, f->off, n)) > 0){
      f->off += r;
      // taint: bytes of an untrusted file reached this process. The flag
      // is on the inode, not on struct file, so dup'd and inherited fds
      // are covered. Opening without reading does not taint.
      if(f->ip->untrusted && !myproc()->tainted){
        myproc()->tainted = 1;
        cprintf("taint: pid %d tainted by reading inode %d\n",
                myproc()->pid, f->ip->inum);
      }
    }
    iunlock(f->ip);
    return r;
  }
  panic("fileread");
}

//PAGEBREAK!
// Write to file f.
int
filewrite(struct file *f, char *addr, int n)
{
  int r;

  if(f->writable == 0)
    return -1;
  if(f->type == FD_PIPE)
    return pipewrite(f->pipe, addr, n);
  if(f->type == FD_INODE){
    // write a few blocks at a time to avoid exceeding
    // the maximum log transaction size, including
    // i-node, indirect block, allocation blocks,
    // and 2 blocks of slop for non-aligned writes.
    // this really belongs lower down, since writei()
    // might be writing a device like the console.
    int max = ((MAXOPBLOCKS-1-1-2) / 2) * 512;
    int i = 0;
    while(i < n){
      int n1 = n - i;
      if(n1 > max)
        n1 = max;

      begin_op();
      ilock(f->ip);
      // taint: write-down rule. A tainted process may not change a clean
      // file that already holds data. An empty clean file is allowed,
      // because the shell creates the target of "> file" before exec;
      // the write below then marks it untrusted.
      if(myproc()->tainted && f->ip->type == T_FILE &&
         !f->ip->untrusted && f->ip->size > 0){
        cprintf("taint: write to clean inode %d refused for pid %d\n",
                f->ip->inum, myproc()->pid);
        iunlock(f->ip);
        end_op();
        return -1;
      }
      if ((r = writei(f->ip, addr + i, f->off, n1)) > 0)
        f->off += r;
      // taint: bytes written by a tainted process are untrusted, so the
      // file becomes untrusted. Only regular files: the console is T_DEV.
      if(r > 0 && myproc()->tainted && f->ip->type == T_FILE &&
         !f->ip->untrusted){
        f->ip->untrusted = 1;
        iupdate(f->ip);
        cprintf("taint: pid %d marked inode %d untrusted by writing\n",
                myproc()->pid, f->ip->inum);
      }
      iunlock(f->ip);
      end_op();

      if(r < 0)
        break;
      if(r != n1)
        panic("short filewrite");
      i += r;
    }
    return i == n ? n : -1;
  }
  panic("filewrite");
}

