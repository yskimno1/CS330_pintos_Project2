#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syscall-nr.h> // syscall names
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "filesys/off_t.h"
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };
typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static uint32_t* p_argv(void* addr);
static void halt (void);
static pid_t exec (const char *file);
static int wait (pid_t pid);
static int create (const char *file, unsigned initial_size);
static int remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static int tell (int fd);
static void close (int fd);
static bool fd_validate(int fd);
static bool string_validate(const char* ptr);
static bool is_bad_pointer(const char* ptr);

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
  if(is_kernel_vaddr(if_esp)){
    thread_exit(); 
    return;
  }

  int syscall_func = *(uint32_t* )if_esp;
  uint32_t argv0;
  uint32_t argv1;
  uint32_t argv2;
  switch(syscall_func)
  	{
 		case SYS_HALT:		/* Halt the operating system. */
    	halt();
  		break;

  	case SYS_EXIT:		/* Terminate this process. */
  		argv0 = *p_argv(if_esp+4);
  		exit((int)argv0);
  		break;

  	case SYS_EXEC:		/* Start another process. */
  		argv0 = *p_argv(if_esp+4);
  		f->eax = (uint32_t) exec((const char *)argv0);
  		break;

  	case SYS_WAIT:		/* Wait for a child process to die. */
  		argv0 = *p_argv(if_esp+4);
  		f->eax = wait((pid_t)argv0);
  		break;

  	case SYS_CREATE:	/* Create a file. */
  		argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);

			filelock_acquire();
			int result = create((const char*)argv0, (unsigned)argv1);
			filelock_release();
			if(result == -1){
				exit(-1);
				break;
			}
			else{
				f->eax = (bool)result;
				break;
			}

  	case SYS_REMOVE:	/* Delete a file. */
  		argv0 = *p_argv(if_esp+4);
			filelock_acquire();
			result = remove((const char* )argv0);
			filelock_release();
			if(result == -1){
				exit(-1);
				break;
			}
			else{
				f->eax = (bool)result;
				break;
			}

  	case SYS_OPEN:		/* Open a file. */
  		argv0 = *p_argv(if_esp+4);
			result = open((const char *)argv0);
			f->eax = result;
			break;

  	case SYS_FILESIZE:/* Obtain a file's size. */
  		argv0 = *p_argv(if_esp+4);
			filelock_acquire();
			result = filesize((int)argv0);
			filelock_release();
			if(result == -1){
				exit(-1);
				break;
			}
			else{
				f->eax = result;
				break;
			}

  	case SYS_READ:		/* Read from a file. */
  		argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
      argv2 = *p_argv(if_esp+12);
			f->eax = read((int)argv0, (void *)argv1, (unsigned)argv2);
  		break;

  	case SYS_WRITE:		/* Write to a file. */
      argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
      argv2 = *p_argv(if_esp+12);
  		f->eax = write((int)argv0, (void *)argv1, (unsigned)argv2);
  		break;

  	case SYS_SEEK:		/* Change position in a file. */
      argv0 = *p_argv(if_esp+4);
      argv1 = *p_argv(if_esp+8);
			seek((int)argv0, (unsigned)argv1);
			if(result == -1){
				exit(-1);
				break;
			}
			else{
				f->eax = result;
				break;
			}

  	case SYS_TELL:		/* Report current position in a file. */
  		argv0 = *p_argv(if_esp+4);
			result = tell((int)argv0);
			if(result == -1){
				exit(-1);
				break;
			}
			else{
				f->eax = result;
				break;
			}

  	case SYS_CLOSE:
  		argv0 = *p_argv(if_esp+4);
			close((int)argv0);
			break;

  	default:
  		break;
  	}
}

uint32_t* 
p_argv(void* addr){
  if (addr==NULL){
    exit(-1);
	}
  if (!is_user_vaddr(addr)){
    exit(-1);
	}
	if(is_bad_pointer(addr)){
		exit(-1);
	}
  return (uint32_t *)(addr);
}

void 
halt (void){
	power_off();
}

void 
exit (int status){
  struct thread* t = thread_current();
  t->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);
	int i; 
  filelock_acquire();
  for (i = 3; i < 131; i++) {
      if (t->fdt[i] != NULL){
        file_close(t->fdt[i]);
        t->fdt[i] = NULL;
      }  
  }   
	filelock_release();
  thread_exit ();
} 

pid_t 
exec (const char *cmd_line){
  if (!string_validate(cmd_line)){
    exit(-1);
	}
	tid_t pid = process_execute (cmd_line);
  return pid;
}

int wait (pid_t pid){
	return process_wait(pid);
}

int create (const char *file, unsigned initial_size){
  if (!string_validate(file)){
    return -1;
  }
	if (is_bad_pointer(file+initial_size)) return -1;
  if (strlen(file)>14)
    return 0;

	return filesys_create(file, initial_size);
}

int remove (const char *file){
  if (!string_validate(file) || strlen(file)>14){
    return -1;
  }
	return filesys_remove(file);
}

int open (const char *file){
  if (!string_validate(file) || strlen(file)>14)
    return -1;
	filelock_acquire();

	struct file* f = filesys_open(file);
	if (f == NULL) {
		filelock_release();
		return -1;
	}

  struct thread *t = thread_current();
  int fd = (t->fd_vld)++;
  t->fdt[fd] = f;
  if (!strcmp(t->name, file)) 
      file_deny_write(f);
  filelock_release();
  return fd; 
}

int filesize (int fd){
  if (!fd_validate(fd)){
    return -1;
  }
	return file_length(thread_current()->fdt[fd]);
}

int read (int fd, void *buffer, unsigned size){
	filelock_acquire();
	int cnt=-1; unsigned i;
	char* buffer_pointer = buffer;
	if (!fd_validate(fd)){
		filelock_release();
		return -1;
	}
  if (!string_validate(buffer)){
		filelock_release();
		exit(-1);
    return -1;
	}
	if (is_bad_pointer(buffer+size)){
		filelock_release();
		exit(-1);
		return -1;
	}

	if (fd == 0){			//keyboard input
		for (i=0; i<size; i++) {
			buffer_pointer[i] = input_getc();
		}
		cnt=size;
		filelock_release();
		return size;
	}

	else {
		struct thread* t = thread_current();
		if (t->fdt[fd]==NULL)
			cnt = -1;
		else{
			cnt = file_read(t->fdt[fd], buffer, size);
		}
	}
	filelock_release();
	return cnt;
}

int write (int fd, const void *buffer, unsigned size){
	filelock_acquire();
  int cnt=-1;
  if (!fd_validate(fd)){
		filelock_release();
  	return cnt;
  }
  if (!string_validate(buffer)){
		filelock_release();
		exit(-1);
    return cnt;
	}
	if (is_bad_pointer(buffer+size)){
		filelock_release();
		exit(-1);
		return -1;
	}
	if (fd ==0){
		filelock_release();
		exit(-1);
		return -1;
	}

	if (fd == 1){
		putbuf (buffer, size);
    filelock_release();
    return size;  
	}

	struct thread* t = thread_current();
	struct file* f = t->fdt[fd];
	cnt = file_write(f, buffer, size);	
	filelock_release();
	return cnt;
}

void seek (int fd, unsigned position){
	if (!fd_validate(fd))
		return;
	struct file* f = thread_current()->fdt[fd];
  file_seek (f, position);  
}

int tell (int fd){
	if (!fd_validate(fd))
		return -1;
	struct file* f = thread_current()->fdt[fd];
	return file_tell(f);
}

void close (int fd){
	if (!fd_validate(fd)){
		exit(-1);
		return;
	}
	filelock_acquire();
	struct thread* t = thread_current();
	struct file* f = t->fdt[fd];
	t->fdt[fd] = NULL;
	file_close(f);
  filelock_release();
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

bool
string_validate(const char* ptr){
	if (!is_user_vaddr(ptr))
    return false;
  if (ptr == NULL)
    return false;
	if (strcmp(ptr, "")==0){
		return -1;
	}
  return true;
}

bool
is_bad_pointer(const char* ptr){
	void* ptr_page = pagedir_get_page(thread_current()->pagedir, ptr);
	if(!ptr_page) return true;
	else return false;
}