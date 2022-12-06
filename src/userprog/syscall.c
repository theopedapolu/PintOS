#include "userprog/syscall.h"
#include <float.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <kernel/stdio.h>
#include "devices/block.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/cache.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/userfile.h"

/* According to pintos spec, you can only write at most
   a few hundred bytes at a time without risk over text
   overlapping on stdout. Although we use a global lock
   right now, this may become a concern later. */
#define STDOUT_WRITE_CHUNK_SIZE 256

/* Returns true if VADDR is in valid user memory. */
static bool is_valid_uaddr(const void* vaddr) {
  return vaddr != NULL && is_user_vaddr(vaddr) &&
         pagedir_get_page(thread_current()->pcb->pagedir, vaddr) != NULL;
}

/* Returns true if the block of memory starting at VADDR with SIZE is
   in valid user memory. */
static bool is_valid_user_memory(const void* vaddr, size_t size) {
  uint8_t* addr = (uint8_t*)vaddr;
  for (size_t offset = 0; offset < size; offset++) {
    if (!is_valid_uaddr(addr + offset)) {
      return false;
    }
  }
  return true;
}

/* Returns true if ARGS is in valid user memory. */
static bool are_valid_args(const uint32_t* args, size_t num_args) {
  return is_valid_user_memory(args, num_args * sizeof(uint32_t));
}

/* Returns true if the string STR is in valid user memory. */
static bool is_valid_string(const char* str) {
  while (is_valid_uaddr(str) && *str != 0) {
    str += 1;
  }
  return is_valid_uaddr(str);
}

/* Type declaration for a syscall handler. EAX is a pointer 
   to the process's EAX register that should be treated as the
   return value for a function. ARGS corresponds to an array 
   of arguments for a given syscall as defined in lib/user/syscall.c.
   For example, for the read syscall, args[0] = fd, args[1] = buffer,
   args[2] = size. */
typedef void syscall_handler_func(uint32_t* eax, uint32_t* args);

/* Type declaration for grouping a syscall handler with the
   number of args it has. This is stored in an array below
   where the index of the array is the respective syscall. */
struct syscall_info {
  int num_args;
  syscall_handler_func* handler;
};

/* Function declaration for the generic syscall handler.
   This is the first function called on a syscall. */
static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* These are all the declarations for the specific syscall
   handlers that will need to be implemented below.
   NOTE: If args includes a pointer to something, the pointer
   must be checked for valid memory in the specific function. */
syscall_handler_func syscall_halt_handler;
syscall_handler_func syscall_exit_handler;
syscall_handler_func syscall_exec_handler;
syscall_handler_func syscall_wait_handler;
syscall_handler_func syscall_create_handler;
syscall_handler_func syscall_remove_handler;
syscall_handler_func syscall_open_handler;
syscall_handler_func syscall_filesize_handler;
syscall_handler_func syscall_read_handler;
syscall_handler_func syscall_write_handler;
syscall_handler_func syscall_seek_handler;
syscall_handler_func syscall_tell_handler;
syscall_handler_func syscall_close_handler;
syscall_handler_func syscall_practice_handler;
syscall_handler_func syscall_compute_e_handler;
syscall_handler_func syscall_pt_create_handler;
syscall_handler_func syscall_pt_exit_handler;
syscall_handler_func syscall_pt_join_handler;
syscall_handler_func syscall_lock_init_handler;
syscall_handler_func syscall_lock_acquire_handler;
syscall_handler_func syscall_lock_release_handler;
syscall_handler_func syscall_sema_init_handler;
syscall_handler_func syscall_sema_down_handler;
syscall_handler_func syscall_sema_up_handler;
syscall_handler_func syscall_get_tid_handler;
syscall_handler_func syscall_nmap_handler;
syscall_handler_func syscall_munmap_handler;
syscall_handler_func syscall_chdir_handler;
syscall_handler_func syscall_mkdir_handler;
syscall_handler_func syscall_readdir_handler;
syscall_handler_func syscall_isdir_handler;
syscall_handler_func syscall_inumber_handler;
syscall_handler_func syscall_buffer_cache_reset_handler;
syscall_handler_func syscall_buffer_cache_hit_rate_handler;
syscall_handler_func syscall_filesys_writes_handler;

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
    {0, syscall_buffer_cache_reset_handler},
    {0, syscall_buffer_cache_hit_rate_handler},
    {0, syscall_filesys_writes_handler},
};

void syscall_halt_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) { shutdown_power_off(); }

void syscall_exit_handler(uint32_t* eax UNUSED, uint32_t* args) { process_exit(args[0]); }

void syscall_exec_handler(uint32_t* eax, uint32_t* args) {
  char* cmd = (char*)args[0];

  /* If cmd is not in user memory, kill the process */
  if (!is_valid_string(cmd)) {
    process_exit(-1);
  }

  /* Copy cmd to kernel stack */
  size_t cmd_len = strlen(cmd);
  char cmd_cpy[cmd_len + 1];
  strlcpy(cmd_cpy, cmd, cmd_len + 1);

  pid_t pid = process_execute(cmd_cpy);
  if (pid == TID_ERROR) {
    *eax = -1;
  } else {
    *eax = pid;
  }
}

void syscall_wait_handler(uint32_t* eax, uint32_t* args) { *eax = process_wait(args[0]); }

void syscall_create_handler(uint32_t* eax, uint32_t* args) {
  const char* file_u = (const char*)args[0];
  unsigned initial_size = args[1];

  if (!is_valid_string(file_u)) {
    process_exit(-1);
    return;
  }

  size_t file_len = strlen(file_u);
  char file[file_len + 1];
  strlcpy(file, file_u, file_len + 1);

  bool result = filesys_create(file, initial_size);
  *eax = result;
}

void syscall_remove_handler(uint32_t* eax, uint32_t* args) {
  const char* file_u = (const char*)args[0];

  if (!is_valid_string(file_u)) {
    process_exit(-1);
    return;
  }

  size_t file_len = strlen(file_u);
  char file[file_len + 1];
  strlcpy(file, file_u, file_len + 1);

  struct dir* dir_to_remove = dir_exists(file);
  if (dir_to_remove != NULL) {
    char tmp_buf[15];
    if (dir_readdir(dir_to_remove, tmp_buf)) {
      *eax = false;
      dir_close(dir_to_remove);
      return;
    }

    dir_close(dir_to_remove);
  }

  bool result = filesys_remove(file);
  *eax = result;
}

void syscall_open_handler(uint32_t* eax, uint32_t* args) {
  const char* file_u = (const char*)args[0];

  if (!is_valid_string(file_u)) {
    process_exit(-1);
    return;
  }

  size_t file_len = strlen(file_u);
  char file[file_len + 1];
  strlcpy(file, file_u, file_len + 1);

  struct process* pcb = thread_current()->pcb;

  int result = user_dir_open(&pcb->user_directories, file, pcb->num_opened_files++);
  if (result == -1) {
    result = user_file_open(&pcb->user_files, file, pcb->num_opened_files);
  }

  *eax = result;
}

void syscall_filesize_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];

  struct user_file* uf = user_file_get(&thread_current()->pcb->user_files, fd);
  if (uf == NULL) {
    *eax = 0;
    return;
  }

  off_t result = file_length(uf->file);
  *eax = result;
}

void syscall_read_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];
  void* buffer = (void*)args[1];
  unsigned length = args[2];

  if (!is_valid_user_memory(buffer, length)) {
    process_exit(-1);
    return;
  }

  if (fd == STDIN_FILENO) {
    unsigned i;
    for (i = 0; i < length; i++) {
      ((char*)(buffer))[i] = input_getc();
    }
    ((char*)(buffer))[i + 1] = '\0';

    *eax = length;
    return;
  }

  struct user_file* uf = user_file_get(&thread_current()->pcb->user_files, fd);
  if (uf == NULL) {
    *eax = 0;
    return;
  }

  off_t result = file_read(uf->file, buffer, length);
  *eax = result;
}

void syscall_write_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];
  const void* buffer = (const void*)args[1];
  unsigned length = args[2];

  if (!is_valid_user_memory(buffer, length)) {
    process_exit(-1);
    return;
  }

  void* buffer_ptr = (void*)buffer;
  if (fd == STDOUT_FILENO) {
    *eax = length;
    while (length >= STDOUT_WRITE_CHUNK_SIZE) {
      putbuf(buffer_ptr, STDOUT_WRITE_CHUNK_SIZE);
      buffer_ptr += STDOUT_WRITE_CHUNK_SIZE;
      length -= STDOUT_WRITE_CHUNK_SIZE;
    }
    putbuf(buffer_ptr, length);
    return;
  }

  struct user_file* uf = user_file_get(&thread_current()->pcb->user_files, fd);
  if (uf == NULL) {
    *eax = 0;
    return;
  }

  off_t result = file_write(uf->file, buffer, length);
  *eax = result;
}

void syscall_seek_handler(uint32_t* eax UNUSED, uint32_t* args) {
  int fd = args[0];
  unsigned position = args[1];

  struct user_file* uf = user_file_get(&thread_current()->pcb->user_files, fd);
  if (uf == NULL) {
    return;
  }

  file_seek(uf->file, position);
}

void syscall_tell_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];

  struct user_file* uf = user_file_get(&thread_current()->pcb->user_files, fd);
  if (uf == NULL) {
    *eax = 0;
    return;
  }

  off_t result = file_tell(uf->file);
  *eax = result;
}

void syscall_close_handler(uint32_t* eax UNUSED, uint32_t* args) {
  int fd = args[0];

  struct process* pcb = thread_current()->pcb;
  user_dir_close(&pcb->user_directories, fd);
  user_file_close(&pcb->user_files, fd);
}

void syscall_practice_handler(uint32_t* eax, uint32_t* args) { *eax = args[0] + 1; }

void syscall_compute_e_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {
  int res = sys_sum_to_e(args[0]);
  *eax = res;
}

void syscall_pt_create_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_pt_exit_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_pt_join_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_lock_init_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_lock_acquire_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_lock_release_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_sema_init_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_sema_down_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_sema_up_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_get_tid_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_nmap_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_munmap_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {}

void syscall_chdir_handler(uint32_t* eax, uint32_t* args) {
  const char* dir_u = (const char*)args[0];

  if (!is_valid_string(dir_u)) {
    process_exit(-1);
    return;
  }

  size_t dir_len = strlen(dir_u);
  char new_dir_string[dir_len + 1];
  strlcpy(new_dir_string, dir_u, dir_len + 1);

  struct dir* new_dir = dir_exists(new_dir_string);
  if (new_dir == NULL) {
    *eax = false;
  } else {
    struct process* pcb = thread_current()->pcb;

    dir_close(pcb->working_dir);
    pcb->working_dir = new_dir;

    *eax = true;
  }
}

void syscall_mkdir_handler(uint32_t* eax, uint32_t* args) {
  const char* dir_u = (const char*)args[0];

  if (!is_valid_string(dir_u)) {
    process_exit(-1);
    return;
  }

  size_t dir_len = strlen(dir_u);
  char new_dir_string[dir_len + 1];
  strlcpy(new_dir_string, dir_u, dir_len + 1);

  int i;
  for (i = dir_len; i >= 0; i--) {
    if (new_dir_string[i] == '/')
      break;
  }

  struct process* pcb = thread_current()->pcb;
  struct dir* parent_dir = pcb->working_dir;
  if (i > 0) {
    char parent_dir_string[i + 1];
    strlcpy(parent_dir_string, new_dir_string, i);
    parent_dir_string[i] = '\0';

    parent_dir = dir_exists(parent_dir_string);
    if (parent_dir == NULL) {
      *eax = false;
      return;
    }
  }

  block_sector_t sector = 0;
  if (!free_map_allocate(1, &sector) || !dir_create(sector, 16)) {
    dir_close(parent_dir);
    *eax = false;
    return;
  }

  *eax = dir_add(parent_dir, &new_dir_string[i + 1], sector);
  dir_close(parent_dir);
}

void syscall_readdir_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];
  const void* buffer = (const void*)args[1];

  if (!is_valid_user_memory(buffer, 15)) {
    process_exit(-1);
    return;
  }

  char* name = (char*)buffer;

  struct process* pcb = thread_current()->pcb;
  struct user_dir* ud = user_dir_get(&pcb->user_directories, fd);

  if (ud == NULL) {
    *eax = false;
    return;
  }

  *eax = dir_readdir(ud->directory, name);
}

void syscall_isdir_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];

  struct process* pcb = thread_current()->pcb;
  *eax = user_dir_get(&pcb->user_directories, fd) != NULL;
}

void syscall_inumber_handler(uint32_t* eax, uint32_t* args) {
  int fd = args[0];

  struct process* pcb = thread_current()->pcb;
  struct user_dir* ud = user_dir_get(&pcb->user_directories, fd);

  if (ud == NULL) {
    *eax = false;
    return;
  }

  struct inode* ud_inode = dir_get_inode(ud->directory);
  if (ud_inode == NULL) {
    *eax = false;
    return;
  }

  *eax = inode_get_inumber(ud_inode);
}

void syscall_buffer_cache_reset_handler(uint32_t* eax UNUSED, uint32_t* args UNUSED) {
  cache_reset();
}

void syscall_buffer_cache_hit_rate_handler(uint32_t* eax, uint32_t* args UNUSED) {
  union {
    float f;
    uint32_t i;
  } hit_rate = {.f = (float)cache_hit_cnt() / (float)cache_req_cnt()};
  *eax = hit_rate.i;
}

void syscall_filesys_writes_handler(uint32_t* eax, uint32_t* args UNUSED) {
  int write_cnt = (int)block_write_cnt(fs_device);
  *eax = write_cnt;
}

/* Handles syscalls right after they're called. First checks
   if the syscall identifier is valid memory, then checks if
   it is a valid syscall, then if the arguments are valid. */
static void syscall_handler(struct intr_frame* f) {
  const uint32_t* args = ((uint32_t*)f->esp);

  /* Check syscall number is in user memory */
  if (!are_valid_args(args, 1) || args[0] >= sizeof(syscall_table) / sizeof(struct syscall_info)) {
    process_exit(-1);
  }

  int syscall_number = args[0];
  int num_args = syscall_table[syscall_number].num_args;

  /* Check args are in user memory */
  if (!are_valid_args(args + 1, num_args)) {
    process_exit(-1);
  }

  /* Copy args to kernel stack */
  uint32_t args_cpy[num_args];
  memcpy(args_cpy, args + 1, num_args * sizeof(uint32_t));

  /* Call corresponding handler function */
  syscall_table[syscall_number].handler(&(f->eax), args_cpy);
}
