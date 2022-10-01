#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <kernel/stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static bool is_valid_uaddr(const void* vaddr);
static bool is_valid_user_memory(const void* vaddr, size_t size);
static bool are_valid_args(const int32_t* args, size_t num_args);
static bool is_valid_string(const char* str);

typedef uint32_t* syscall_handler_func(uint32_t* eax, char** args);

struct syscall_mapping {
  int num_args;
  syscall_handler_func* handler;
};

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

void syscall_halt_handler(uint32_t* eax, char** args);
void syscall_exit_handler(uint32_t* eax, char** args);
void syscall_exec_handler(uint32_t* eax, char** args);
void syscall_wait_handler(uint32_t* eax, char** args);
void syscall_create_handler(uint32_t* eax, char** args);
void syscall_remove_handler(uint32_t* eax, char** args);
void syscall_open_handler(uint32_t* eax, char** args);
void syscall_filesize_handler(uint32_t* eax, char** args);
void syscall_read_handler(uint32_t* eax, char** args);
void syscall_write_handler(uint32_t* eax, char** args);
void syscall_seek_handler(uint32_t* eax, char** args);
void syscall_tell_handler(uint32_t* eax, char** args);
void syscall_close_handler(uint32_t* eax, char** args);
void syscall_practice_handler(uint32_t* eax, char** args);
void syscall_compute_e_handler(uint32_t* eax, char** args);
void syscall_pt_create_handler(uint32_t* eax, char** args);
void syscall_pt_exit_handler(uint32_t* eax, char** args);
void syscall_pt_join_handler(uint32_t* eax, char** args);
void syscall_lock_init_handler(uint32_t* eax, char** args);
void syscall_lock_acquire_handler(uint32_t* eax, char** args);
void syscall_lock_release_handler(uint32_t* eax, char** args);
void syscall_sema_init_handler(uint32_t* eax, char** args);
void syscall_sema_down_handler(uint32_t* eax, char** args);
void syscall_sema_up_handler(uint32_t* eax, char** args);
void syscall_get_tid_handler(uint32_t* eax, char** args);
void syscall_nmap_handler(uint32_t* eax, char** args);
void syscall_munmap_handler(uint32_t* eax, char** args);
void syscall_chdir_handler(uint32_t* eax, char** args);
void syscall_mkdir_handler(uint32_t* eax, char** args);
void syscall_readdir_handler(uint32_t* eax, char** args);
void syscall_isdir_handler(uint32_t* eax, char** args);
void syscall_inumber_handler(uint32_t* eax, char** args);

struct syscall_mapping map[] = {
  {0, syscall_halt_handler},
  {0, syscall_exit_handler},
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

void syscall_exit_handler(uint32_t* eax, char** args) {
  eax = args[1];
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
  process_exit();
}

void syscall_write_handler(uint32_t* eax, char** args) {
  if (args[0] == STDOUT_FILENO) {
    putbuf((const void*)args[1], (size_t)args[2]);
    eax = args[2];
  } 
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  if(!are_valid_args(args, 1) || !are_valid_args(args + 1, map[args[0]].num_args)) {
    // Kill process
  }

  map[args[0]].handler(&(f->eax), args + 1);
}
