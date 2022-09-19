#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <kernel/stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  /*
   * Skeleton code by Ben

   * I've put in all of the system calls we need to handle here
   * with some basic responses to each of them, mostly just including
   * the respective kernel functions that we'll have to call to do
   * what we need to do.
   * 
   * SYS_EXIT is handled automatically in the starter code, so nothing
   * needs to change there.
   * 
   * Most of this stuff is very hastily put together and many of the 
   * argument types are just wrong, kernel functions aren't fully
   * implemented, or other caveats exist that we will have to address.
   * 
   * The only function I've worked with extensively is SYS_WRITE to
   * console, since we need it to validate our tests. It works for me
   * but there may be some edge-case checking we'll need to do.
   * 
   * Something important to consider for all these functions which I
   * have not done yet is malicious/erroneous code checking. Since these
   * are system calls called by user code, we need to be 100% sure that
   * anything called here cannot damage the system through improper
   * memory accesses, null pointers, or any other mistakes and shenanigans
   * that could get by. This is something we will seriously have to 
   * consider for every one of these functions, including SYS_WRITE to
   * console.
   * 
   * Another thing worth noting is for file operations. Looking at
   * lib/user/syscall.c, we see that file descriptors (int) are passed
   * to these functions, but the kernel functions take file structs.
   * This means that we will have to keep a close eye on when files are
   * opened and closed as we will need to map those files to each
   * program's file descriptor. As for stdin and stdout, we will need
   * special cases for fd = 0 and fd = 1, which I have done for SYS_WRITE.
   * 
   * Some functions, like process_wait, aren't implemented and require
   * further designing before use.
   * 
   * Lastly, we may want to redesign this whole if...else if...else if...
   * deal. I think it would be good to create a struct that maps each
   * syscall to its respective handler, which would be a separate function
   * probably in this file. That way this syscall_handler function is just
   * a couple lines long and passes everything to the responsible function.
   */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  } else if(args[0] == SYS_EXEC) {
    pid_t pid = process_execute((const char*)args[1]);
    if(pid != TID_ERROR) {
      f->eax = pid;
    } else {
      f->eax = -1;
    }
  } else if(args[0] == SYS_WAIT) {
    f->eax = process_wait((pid_t)args[1]);
  } else if(args[0] == SYS_CREATE) {
    f->eax = filesys_create((const char*)args[1], (off_t)args[2]);
  } else if(args[0] == SYS_REMOVE) {
    f->eax = filesys_remove((const char*)args[1]);
  } else if(args[0] == SYS_OPEN) {
    f->eax = (uint32_t)file_open((struct inode*)args[1]); // This is wrong
  } else if(args[0] == SYS_FILESIZE) {
    f->eax = file_length((struct file*)args[1]); // This is wrong
  } else if(args[0] == SYS_READ) {
    f->eax = file_read((struct file*)args[1], (void*)args[2], (off_t)args[3]); // This is wrong
  } else if(args[0] == SYS_WRITE) {
    if(args[1] == STDOUT_FILENO) {
      putbuf((const void*)args[2], (size_t)args[3]);
      f->eax = args[3];
    } else
      f->eax = file_write((struct file*)args[1], (const void*)args[2], (off_t)args[3]); // This is wrong
  } else if(args[0] == SYS_SEEK) {
    file_seek((struct file*)args[1], (off_t)args[2]); // This is wrong
  } else if(args[0] == SYS_TELL) {
    f->eax = file_tell((struct file*)args[1]); // This is wrong
  } else if(args[0] == SYS_CLOSE) {
    file_close((struct file*)args[1]); // This is wrong
  } else if(args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
}
