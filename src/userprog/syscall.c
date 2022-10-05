#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <kernel/stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

/* Returns true if VADDR is in valid user memory. */
static bool is_valid_uaddr(const void* vaddr) {
  return vaddr != NULL && is_user_vaddr(vaddr) &&
         pagedir_get_page(thread_current()->pcb->pagedir, vaddr) != NULL;
}

/* Returns true if the block of memory starting at VADDR with SIZE is
   in valid user memory. */
static bool is_valid_user_memory(const void* vaddr, size_t size) {
  uint8_t* addr = (uint8_t*)vaddr;
  for (int offset = 0; offset < size; offset++) {
    if (!is_valid_uaddr(addr + offset)) {
      return false;
    }
  }
  return true;
}

/* Returns true if ARGS is in valid user memory. */
static bool are_valid_args(const int32_t* args, size_t num_args) {
  return is_valid_user_memory(args, num_args * sizeof(uint32_t));
}

/* Returns true if the string STR is in valid user memory. */
static bool is_valid_string(const char* str) {
  // TODO: implement is_valid_string
  return true;
}

/* Type declaration for a syscall handler. EAX is a pointer 
   to the process's EAX register that should be treated as the
   return value for a function. ARGS corresponds to an array 
   of arguments for a given syscall as defined in lib/user/syscall.c.
   For example, for the read syscall, args[0] = fd, args[1] = buffer,
   args[2] = size. */
typedef void syscall_handler_func_t(uint32_t* eax, uint32_t* args);

/* Type declaration for grouping a syscall handler with the
   number of args it has. This is stored in an array below
   where the index of the array is the respective syscall. */
struct syscall_info {
  int num_args;
  syscall_handler_func_t* handler;
};

/* Function declaration for the generic syscall handler.
   This is the first function called on a syscall. */
static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* These are all the declarations for the specific syscall
   handlers that will need to be implemented below.
   NOTE: If args includes a pointer to something, the pointer
   must be checked for valid memory in the specific function. */
syscall_handler_func_t syscall_halt_handler;
syscall_handler_func_t syscall_exit_handler;
syscall_handler_func_t syscall_exec_handler;
syscall_handler_func_t syscall_wait_handler;
syscall_handler_func_t syscall_create_handler;
syscall_handler_func_t syscall_remove_handler;
syscall_handler_func_t syscall_open_handler;
syscall_handler_func_t syscall_filesize_handler;
syscall_handler_func_t syscall_read_handler;
syscall_handler_func_t syscall_write_handler;
syscall_handler_func_t syscall_seek_handler;
syscall_handler_func_t syscall_tell_handler;
syscall_handler_func_t syscall_close_handler;
syscall_handler_func_t syscall_practice_handler;
syscall_handler_func_t syscall_compute_e_handler;
syscall_handler_func_t syscall_pt_create_handler;
syscall_handler_func_t syscall_pt_exit_handler;
syscall_handler_func_t syscall_pt_join_handler;
syscall_handler_func_t syscall_lock_init_handler;
syscall_handler_func_t syscall_lock_acquire_handler;
syscall_handler_func_t syscall_lock_release_handler;
syscall_handler_func_t syscall_sema_init_handler;
syscall_handler_func_t syscall_sema_down_handler;
syscall_handler_func_t syscall_sema_up_handler;
syscall_handler_func_t syscall_get_tid_handler;
syscall_handler_func_t syscall_nmap_handler;
syscall_handler_func_t syscall_munmap_handler;
syscall_handler_func_t syscall_chdir_handler;
syscall_handler_func_t syscall_mkdir_handler;
syscall_handler_func_t syscall_readdir_handler;
syscall_handler_func_t syscall_isdir_handler;
syscall_handler_func_t syscall_inumber_handler;

/* Array mapping each syscall (noted by its index) to
   the number of arguments it has and the function handler 
   assigned to deal with it. */
struct syscall_info syscall_table[] = {
    {0, syscall_halt_handler},
    {1, syscall_exit_handler},
    {1, syscall_exec_handler},
    {1, syscall_wait_handler},
    {2, syscall_create_handler},
    {1, syscall_remove_handler},
    {1, syscall_open_handler},
    {1, syscall_filesize_handler},
    {3, syscall_read_handler},
    {3, syscall_write_handler},
    {2, syscall_seek_handler},
    {1, syscall_tell_handler},
    {1, syscall_close_handler},
    {1, syscall_practice_handler},
    {1, syscall_compute_e_handler},
    {3, syscall_pt_create_handler},
    {0, syscall_pt_exit_handler},
    {1, syscall_pt_join_handler},
    {1, syscall_lock_init_handler},
    {1, syscall_lock_acquire_handler},
    {1, syscall_lock_release_handler},
    {2, syscall_sema_init_handler},
    {1, syscall_sema_down_handler},
    {1, syscall_sema_up_handler},
    {0, syscall_get_tid_handler},
    {2, syscall_nmap_handler},
    {1, syscall_munmap_handler},
    {1, syscall_chdir_handler},
    {1, syscall_mkdir_handler},
    {2, syscall_readdir_handler},
    {1, syscall_isdir_handler},
    {1, syscall_inumber_handler},
};

void syscall_halt_handler(uint32_t* eax, uint32_t* args) {}

void syscall_exit_handler(uint32_t* eax, uint32_t* args) {
  process_exit(args[0]);
}

void syscall_exec_handler(uint32_t* eax, uint32_t* args) {}

void syscall_wait_handler(uint32_t* eax, uint32_t* args) {}

void syscall_create_handler(uint32_t* eax, uint32_t* args) {}

void syscall_remove_handler(uint32_t* eax, uint32_t* args) {}

void syscall_open_handler(uint32_t* eax, uint32_t* args) {}

void syscall_filesize_handler(uint32_t* eax, uint32_t* args) {}

void syscall_read_handler(uint32_t* eax, uint32_t* args) {}

void syscall_write_handler(uint32_t* eax, uint32_t* args) {
  if (args[0] == STDOUT_FILENO) {
    putbuf((const void*)args[1], (size_t)args[2]);
    *eax = args[2];
  }

  // TODO: Implement file writes other than stdout
}

void syscall_seek_handler(uint32_t* eax, uint32_t* args) {}

void syscall_tell_handler(uint32_t* eax, uint32_t* args) {}

void syscall_close_handler(uint32_t* eax, uint32_t* args) {}

void syscall_practice_handler(uint32_t* eax, uint32_t* args) {
  *eax = args[0] + 1;
}

void syscall_compute_e_handler(uint32_t* eax, uint32_t* args) {}

void syscall_pt_create_handler(uint32_t* eax, uint32_t* args) {}

void syscall_pt_exit_handler(uint32_t* eax, uint32_t* args) {}

void syscall_pt_join_handler(uint32_t* eax, uint32_t* args) {}

void syscall_lock_init_handler(uint32_t* eax, uint32_t* args) {}

void syscall_lock_acquire_handler(uint32_t* eax, uint32_t* args) {}

void syscall_lock_release_handler(uint32_t* eax, uint32_t* args) {}

void syscall_sema_init_handler(uint32_t* eax, uint32_t* args) {}

void syscall_sema_down_handler(uint32_t* eax, uint32_t* args) {}

void syscall_sema_up_handler(uint32_t* eax, uint32_t* args) {}

void syscall_get_tid_handler(uint32_t* eax, uint32_t* args) {}

void syscall_nmap_handler(uint32_t* eax, uint32_t* args) {}

void syscall_munmap_handler(uint32_t* eax, uint32_t* args) {}

void syscall_chdir_handler(uint32_t* eax, uint32_t* args) {}

void syscall_mkdir_handler(uint32_t* eax, uint32_t* args) {}

void syscall_readdir_handler(uint32_t* eax, uint32_t* args) {}

void syscall_isdir_handler(uint32_t* eax, uint32_t* args) {}

void syscall_inumber_handler(uint32_t* eax, uint32_t* args) {}

/* Handles syscalls right after they're called. First checks
   if the syscall identifier is valid memory, then checks if
   it is a valid syscall, then if the arguments are valid. */
static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /* Check syscall number is in user memory */
  if (!are_valid_args(args, 1) || args[0] >= 32) {
    process_exit(-1);
  }

  int syscall_number = args[0];
  int num_args = syscall_table[syscall_number].num_args;

  /* Check args are in user memory */
  if (!are_valid_args(args + 1, num_args)) {
    process_exit(-1);
  }

  /* Copy args to kernel stack */
  uint32_t* args_copy[num_args];
  memcpy(args_copy, args + 1, num_args * sizeof(uint32_t));

  /* Call corresponding handler function */
  syscall_table[syscall_number].handler(&(f->eax), args_copy);
}
