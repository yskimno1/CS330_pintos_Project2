#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };
  
void syscall_init (void);
void exit (int status);

#endif /* userprog/syscall.h */
