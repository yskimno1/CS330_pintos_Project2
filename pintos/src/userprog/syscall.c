#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <syscall-nr.h> // syscall names
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "userprog/process.h"


typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static void halt (void);
static void exit (int status);
static pid_t exec (const char *file);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static bool put_user (uint8_t *udst, uint8_t byte);
static int32_t get_user (const uint8_t *uaddr);
static bool fd_validate(int fd);

struct lock filelock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filelock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  void* if_esp = f->esp;
  if(is_kernel_vaddr(if_esp)){ // have to change yunseong
    thread_exit(); // exit(-1), page fault, more... yunseong
    // have to consider malloced memory or lock
    return;
  }
  int syscall_func = *(uint32_t* )if_esp;
  printf ("system call! %d\n", syscall_func);

  uint32_t* argv;

  switch(syscall_func)
  	{
 		case SYS_HALT:		/* Halt the operating system. */
    	//printf("SYS_HALT\n");
    	halt();
  		break;

  	case SYS_EXIT:		/* Terminate this process. */
  		//printf("SYS_EXIT\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		exit((int)argv[0]);
  		break;

  	case SYS_EXEC:		/* Start another process. */
  		printf("SYS_EXEC\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		f->eax = (uint32_t) exec((const char *)argv[0]);
  		break;

  	case SYS_WAIT:		/* Wait for a child process to die. */
  		printf("SYS_WAIT\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		wait((pid_t)argv[0]);
  		break;

  	case SYS_CREATE:	/* Create a file. */
  		printf("SYS_CREATE\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		argv[1] = *(uint32_t *)(if_esp+8);
  		create((const char*)argv[0], (unsigned)argv[1]);
  		break;

  	case SYS_REMOVE:	/* Delete a file. */
  		printf("SYS_REMOVE\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		remove((const char *)argv[0]);
  		break;

  	case SYS_OPEN:		/* Open a file. */
  		printf("SYS_OPEN\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		open((const char *)argv[0]);
  		break;
  	case SYS_FILESIZE:/* Obtain a file's size. */
  		printf("SYS_FILESIZE\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		filesize((int)argv[0]);
  		break;
  	case SYS_READ:		/* Read from a file. */
  		//printf("SYS_READ\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		argv[1] = *(uint32_t *)(if_esp+8);
  		argv[2] = *(uint32_t *)(if_esp+12);
  		f->eax = read((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
  		break;
  	case SYS_WRITE:		/* Write to a file. */
  		printf("SYS_WRITE\n");
  		printf("%d\t %d\t %d\t %d\n", *(uint32_t *)(if_esp), *((uint32_t *)(if_esp+4)), *((uint32_t *)(if_esp+8)), *((uint32_t *)(if_esp+12)) );
  		printf("%p\t %p\t %p\t %p\n", (uint32_t *)(if_esp), ((uint32_t *)(if_esp+4)), ((uint32_t *)(if_esp+8)), ((uint32_t *)(if_esp+12)) );
  		hex_dump(if_esp, if_esp, 100, 1);
  		argv[0] = *((uint32_t *)(if_esp+4));
  		argv[1] = *((uint32_t *)(if_esp+8));
  		argv[2] = *((uint32_t *)(if_esp+12));
  		f->eax = write((int)argv[0], (void *)argv[1], (unsigned)argv[2]);
  		break;
  	case SYS_SEEK:		/* Change position in a file. */
  		printf("SYS_SEEK\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		argv[1] = *(uint32_t *)(if_esp+8);
  		seek((int)argv[0], (unsigned)argv[1]);
  		break;
  	case SYS_TELL:		/* Report current position in a file. */
  		printf("SYS_TELL\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		tell((int)argv[0]);
  		break;
  	case SYS_CLOSE:
  		printf("SYS_CLOSE\n");
  		argv[0] = *(uint32_t *)(if_esp+4);
  		close((int)argv[0]);
  		break;

  	default:
  		printf("NONE\n");
  		break;
  	}
  
  thread_exit ();
}


void 
halt (void){
	power_off();
}

void 
exit (int status){
	thread_current ()->status = status;
	printf("%s: exit(%d)\n", thread_name(), status);

	// for문 위치 바뀔수도?? hyunjin
	int i;
  for (i = 3; i < 128; i++) {
      if (thread_current()->fdt[i] != NULL)
          close(i);  
  }   
  thread_exit ();
 
} 

pid_t 
exec (const char *cmd_line){
	tid_t pid = process_execute (cmd_line);
  return pid;
}

int wait (pid_t pid){
	return pid;
}

bool create (const char *file, unsigned initial_size){
	return filesys_create(file, initial_size);
}

bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file){
	lock_acquire(&filelock);
	struct file* f = filesys_open(file);
	if (f == NULL) {
		lock_acquire(&filelock);
		return -1;
	} 
  struct thread *t = thread_current();
  int fd = (t->fd_vld)++;
  t->fdt[fd] = f;
  lock_release(&filelock);
  return fd; 
}

int filesize (int fd){
	return file_length(thread_current()->fdt[fd]);
}

int read (int fd, void *buffer, unsigned size){
	int cnt=0; int i;
	if (!fd_validate(fd))
		return -1;
	lock_acquire(&filelock);

	if (fd == 0){			//keyboard input
		for (i=0; i++; i<size) {
			// must be below PHYS_BASE. 
			if (!is_user_vaddr(buffer+i))
				return -1;
			put_user((uint8_t *)(buffer+i), input_getc());	
			cnt++;
		}
	}

	else {
		struct thread* t = thread_current();
		if (t->fdt[fd]==NULL)
			cnt = -1;
		else
			cnt = file_read(t->fdt[fd], buffer, size);
	}	
	lock_release(&filelock);
	return cnt;
}

int write (int fd, const void *buffer, unsigned size){
  int cnt=-1;
  if (!fd_validate(fd)){
  	return cnt;
  }
	lock_acquire(&filelock);

	if (fd == 1){
		putbuf (buffer, size);
    lock_release (&filelock);
    return size;  
	}

	else {
		struct thread* t = thread_current();
		struct file* f = t->fdt[fd];
		cnt = file_write(f, buffer, size);
	}	
	lock_release(&filelock);
	return cnt;
}

void seek (int fd, unsigned position){
	if (!fd_validate(fd))
		exit(-1);
	struct file* f = thread_current()->fdt[fd];
  file_seek (f, position);  
}

unsigned tell (int fd){
	if (!fd_validate(fd))
		exit(-1);
	struct file* f = thread_current()->fdt[fd];
	return file_tell(f);
}

void close (int fd){
	if (fd_validate(fd))
		exit(-1);
	struct thread* t = thread_current();
	struct file* f = t->fdt[fd];
	t->fdt[fd] = NULL;
	file_close(f);
}

/* 	Reads a byte at user virtual address UADDR.  
		Returns the byte value if successful, -1 if a segfault occurred. 	*/
static int get_user (const uint8_t *uaddr) {
	int result; 
	//UADDR must be below PHYS_BASE.
	if (!is_user_vaddr((const void *)uaddr))
		return false;
	asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
	return result; 
}

/* 	Writes BYTE to user address UDST. 
		Returns true if successful, false if a segfault occurred. 		*/
static bool put_user (uint8_t *udst, uint8_t byte) {
	int error_code; 	
	asm ("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

bool
fd_validate(int fd){
	struct thread* t = thread_current();
	return (fd>1 && fd<128 && fd < (t->fd_vld) && t->fdt[fd] != NULL);
}