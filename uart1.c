// taint: driver for the second serial port (COM2), used as a private
// line between the host-side agent bridge and agentd. Kernel messages
// stay on the console (COM1), so agent replies and kernel logs can no
// longer get mixed up.
//
// /uart1 (major UART1) is a raw byte device: no echo and no line
// editing. A read returns the bytes that have arrived (at least one);
// ^D means end of file, as on the console. Without a second serial
// port (plain "make qemu-nox") reads and writes fail with -1.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "traps.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "mmu.h"
#include "proc.h"
#include "x86.h"

#define COM2     0x2f8
#define INBUF    512
#define CTRL_D   ('D' - '@')

static struct {
  struct spinlock lock;
  char buf[INBUF];
  uint r;   // next byte to read
  uint w;   // next free slot
} in;

static int present;   // is there a second serial port?

static int
uart1getc(void)
{
  if(!(inb(COM2+5) & 0x01))   // no byte waiting
    return -1;
  return inb(COM2+0);
}

static void
uart1putc(int c)
{
  int i;

  for(i = 0; i < 128 && !(inb(COM2+5) & 0x20); i++)
    microdelay(10);
  outb(COM2+0, c);
}

// Interrupt: move every waiting byte into the buffer, wake the reader.
void
uart1intr(void)
{
  int c;

  acquire(&in.lock);
  while((c = uart1getc()) >= 0){
    if(in.w - in.r < INBUF)   // buffer full: drop the byte
      in.buf[in.w++ % INBUF] = c;
  }
  wakeup(&in.r);
  release(&in.lock);
}

static int
uart1read(struct inode *ip, char *dst, int n)
{
  int i, c;

  if(!present)
    return -1;
  iunlock(ip);
  acquire(&in.lock);
  while(in.r == in.w){
    if(myproc()->killed){
      release(&in.lock);
      ilock(ip);
      return -1;
    }
    sleep(&in.r, &in.lock);
  }
  for(i = 0; i < n && in.r != in.w; i++){
    c = in.buf[in.r % INBUF];
    if(c == CTRL_D){
      if(i == 0)
        in.r++;   // return 0 (EOF) now; otherwise keep it for next time
      break;
    }
    in.r++;
    dst[i] = c;
  }
  release(&in.lock);
  ilock(ip);
  return i;
}

static int
uart1write(struct inode *ip, char *buf, int n)
{
  int i;

  if(!present)
    return -1;
  iunlock(ip);
  for(i = 0; i < n; i++)
    uart1putc(buf[i] & 0xff);
  ilock(ip);
  return n;
}

void
uart1init(void)
{
  initlock(&in.lock, "uart1");
  devsw[UART1].read = uart1read;
  devsw[UART1].write = uart1write;

  // Same setup as COM1 in uart.c.
  outb(COM2+2, 0);            // FIFO off
  outb(COM2+3, 0x80);         // unlock divisor
  outb(COM2+0, 115200/9600);
  outb(COM2+1, 0);
  outb(COM2+3, 0x03);         // lock divisor, 8 data bits
  outb(COM2+4, 0);
  outb(COM2+1, 0x01);         // enable receive interrupts

  if(inb(COM2+5) == 0xFF)     // no second serial port
    return;
  present = 1;
  inb(COM2+2);
  inb(COM2+0);
  ioapicenable(IRQ_COM2, 0);
}
