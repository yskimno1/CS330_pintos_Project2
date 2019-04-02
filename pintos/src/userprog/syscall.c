#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
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
static uint32_t* p_argv(void* addr);
static void halt (void);
static void exit (int status);
static pid_t exec (const char *file);
static int wait (pid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool temp_remove (const char *file);
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
static bool string_validate(const char* ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  filelock_init();
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
  // printf ("system call! %d\n", syscall_func);

  uint32_t argv0;
  uint32_t argv1;
  uint32_t argv2;
  switch(syscall_func)
  	{
 		case SYS_HALT:		/* Halt the operating system. */
    	//printf("SYS_HALT\n");
    	halt();
  		break;

  	case SYS_EXIT:		/* Terminate this process. */
  		//printf("SYS_EXIT\n");
  		argv0 = *p_argv(if_esp+4);
  		exit((int)argv0);
  		break;

  	case SYS_EXEC:		/* Start another process. */
  		// printf("SYS_EXEC\n");
  		argv0 = *p_argv(if_esp+4);
  		f->eax = (uint32_t) exec((const char *)argv0);
  		break;

  	case SYS_WAIT:		/* Wait for a child process to die. */
  		// printf("SYS_WAIT\n");
  		argv0 = *p_argv(if_esp+4);
  		f->eax = wait((pid_t)argv0);
  		break;

  	case SYS_CREATE:	/* Create a file. */
  		// printf("SYS_CREATE\n");
  		argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
			filelock_acquire();
  		f->eax = create((const char*)argv0, (unsigned)argv1);
			filelock_release();
  		break;

  	case SYS_REMOVE:	/* Delete a file. */
  		// printf("SYS_REMOVE\n");
  		argv0 = *p_argv(if_esp+4);
			filelock_acquire();
  		temp_remove((const char *)argv0);
			filelock_release();
  		break;

  	case SYS_OPEN:	{	/* Open a file. */
  		// printf("SYS_OPEN\n");
  		//argv0 = *p_argv(if_esp+4);
      char** ptr = (char **)(if_esp+4);
      if (ptr==NULL)
        exit(-1);
      if (!is_user_vaddr(ptr))
        exit(-1);
      argv0 = *ptr;
  		open((const char *)argv0);
  		break;
    }
  	case SYS_FILESIZE:/* Obtain a file's size. */
  		// printf("SYS_FILESIZE\n");
  		argv0 = *p_argv(if_esp+4);
			filelock_acquire();
  		filesize((int)argv0);
			filelock_release();
  		break;
  	case SYS_READ:		/* Read from a file. */
  		//printf("SYS_READ\n");
  		argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
      argv2 = *p_argv(if_esp+12);
  		f->eax = read((int)argv0, (void *)argv1, (unsigned)argv2);
  		break;
  	case SYS_WRITE:		/* Write to a file. */
  		// printf("SYS_WRITE\n");
      argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
      argv2 = *p_argv(if_esp+12);
  		f->eax = write((int)argv0, (void *)argv1, (unsigned)argv2);
  		break;
  	case SYS_SEEK:		/* Change position in a file. */
  		// printf("SYS_SEEK\n");
      argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
  		seek((int)argv0, (unsigned)argv1);
  		break;
  	case SYS_TELL:		/* Report current position in a file. */
  		// printf("SYS_TELL\n");
  		argv0 = *p_argv(if_esp+4);
  		tell((int)argv0);
  		break;
  	case SYS_CLOSE:
  		// printf("SYS_CLOSE\n");
  		argv0 = *p_argv(if_esp+4);
  		close((int)argv0);
  		break;

  	default:
  		// printf("NONE\n");
  		break;
  	}
}

uint32_t* 
p_argv(void* addr){
  if (addr==NULL)
    exit(-1);
  if (!is_user_vaddr(addr))
    exit(-1);
  return (uint32_t *)(addr);
}

void 
halt (void){
	power_off();
}

void 
exit (int status){
	thread_current ()->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);

	int i; 
  filelock_acquire();
  for (i = 3; i < 131; i++) {
      if (thread_current()->fdt[i] != NULL)
          close(i);  
  }   
	filelock_release();
  thread_exit ();
 
} 

pid_t 
exec (const char *cmd_line){
  if (!string_validate(cmd_line))
    exit(-1);
	tid_t pid = process_execute (cmd_line);
  return pid;
}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
  if (!string_validate(file)){
    filelock_release();
    exit(-1);
  }
  if (strlen(file)>14)
    return 0;

	return filesys_create(file, initial_size);
  
}

bool temp_remove (const char *file){
  if (!string_validate(file || strlen(file)>14)){
    filelock_release();
    exit(-1);
  }
	return filesys_remove(file);
}

int open (const char *file){
  if (!string_validate(file) || strlen(file)>14)
    return -1;
	filelock_acquire();
	struct file* f = filesys_open(file);
	if (f == NULL) {
		filelock_acquire();
		return -1;
	} 
  struct thread *t = thread_current();
  int fd = (t->fd_vld)++;
  t->fdt[fd] = f;
  filelock_release();
  return fd; 
}

int filesize (int fd){
  if (!fd_validate(fd)){
    filelock_release();
    exit(-1);
  }
	return file_length(thread_current()->fdt[fd]);
}

int read (int fd, void *buffer, unsigned size){
	int cnt=0; unsigned i;
	if (!fd_validate(fd))
		return -1;
  if (!string_validate(buffer))
    return -1;

	filelock_acquire();

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
	filelock_release();
	return cnt;
}

int write (int fd, const void *buffer, unsigned size){
  int cnt=0;
  if (!fd_validate(fd) || !string_validate(buffer)){
  	return cnt;
  }

	filelock_acquire();
	if (fd == 1){
		putbuf (buffer, size);
    filelock_release ();
    return size;  
	}

	else {
		struct thread* t = thread_current();
		struct file* f = t->fdt[fd];
		cnt = file_write(f, buffer, size);
	}	
	filelock_release();
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
	filelock_acquire();
	struct thread* t = thread_current();
	struct file* f = t->fdt[fd];
	t->fdt[fd] = NULL;
	filelock_release();
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
	bool val = true;
	val = val && fd>=0 && fd<131 && (fd < (t->fd_vld));
	if (fd >2 )
		val = val && t->fdt[fd] != NULL;
	return val;
}

//bad ptr condition? hyunjin
bool
string_validate(const char* ptr){
  if (ptr == NULL)
    return false;
  if (*ptr == NULL)
    return false;
  if (!is_user_vaddr(ptr))
    return false;
  return true;
}

