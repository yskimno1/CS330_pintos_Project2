#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h> // syscall names
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void** if_esp = f->esp;
  if(is_kernel_vaddr(if_esp)){ // have to change yunseong
    thread_exit(); // exit(-1), page fault, more... yunseong
    // have to consider malloced memory or lock
    return;
  }
  int syscall_func = *(int* )if_esp;
  printf ("system call!\n");
  if(syscall_func == SYS_EXEC){
    printf("came here\n");
  }
  thread_exit ();
}
