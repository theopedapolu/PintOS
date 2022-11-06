#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/userfile.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct start_process_args {
  char* file_name;                /* Executable's file name */
  struct process* parent_process; /* PCB of the parent process */
  struct semaphore exec_wait;     /* Down'd by process_execute, up'd by start_process */
  bool success;                   /* Set by start_process, returned to process_execute */
};

struct pthread_args {
  stub_fun sf;
  pthread_fun tf;
  void* arg;
  struct semaphore create_wait;
  struct process* pcb;
  bool success;
};

static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(struct pthread_args* args, void (**eip)(void), void** esp);

/* Initializes user programs in the system by ensuring the main 
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  /* Initialize PCB */
  list_init(&t->pcb->child_exit_statuses);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Create arguments to start_process */
  struct start_process_args* args = malloc(sizeof(struct start_process_args));
  if (args == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  args->file_name = fn_copy;
  args->parent_process = thread_current()->pcb;
  sema_init(&args->exec_wait, 0);
  args->success = false;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, args);

  /* Wait for thread_create to finish, then free fn_copy */
  sema_down(&args->exec_wait);
  palloc_free_page(fn_copy);

  /* If start_process failed, should return TID_ERROR */
  if (!args->success) {
    tid = TID_ERROR;
  }

  free(args);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args_) {
  struct start_process_args* args = (struct start_process_args*)args_;
  char* file_name = args->file_name;
  struct thread* t = thread_current();
  struct intr_frame if_;
  char temp[108]; // For storing current FPU state during initialization
  bool success, pcb_success, es_success;

  /* Allocate process control block and exit status */
  struct process* new_pcb = malloc(sizeof(struct process));
  struct exit_status* new_es = malloc(sizeof(struct exit_status));
  success = pcb_success = new_pcb != NULL;
  es_success = new_es != NULL;
  success = pcb_success && es_success;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    new_pcb->num_opened_files = 2; // Skip stdin and stdout
    list_init(&(new_pcb->user_files));
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    t->pcb->exit_status = new_es;
    list_init(&t->pcb->child_exit_statuses);

    // Initialize exit status
    t->pcb->exit_status->pid = t->tid;
    t->pcb->exit_status->status = -1;
    t->pcb->exit_status->waited = false;
    t->pcb->exit_status->exited = false;
    t->pcb->exit_status->ref_cnt = 2;
    lock_init(&t->pcb->exit_status->ref_cnt_lock);
    sema_init(&t->pcb->exit_status->exit_wait, 0);

    // Add exit status to parent
    list_push_back(&args->parent_process->child_exit_statuses, &t->pcb->exit_status->elem);

    // Initialize user_thread related fields in the new PCB
    list_init(&(t->pcb->user_threads));
    lock_init(&(t->pcb->pthread_lock));
    lock_init(&(t->pcb->exit_lock));
    t->pcb->exit = false;

    // Add current main thread to list
    struct user_thread* ut_main = (struct user_thread*)malloc(sizeof(struct user_thread));
    success = success && ut_main != NULL;
    if (success) {
      ut_main->tid = t->tid;
      ut_main->exited = false;
      ut_main->waited = false;
      sema_init(&ut_main->join_wait, 0);
      ut_main->stack = NULL;
      list_push_back(&t->pcb->user_threads, &ut_main->elem);
    } else {
      free(ut_main);
    }

    // Initialize user-level synchronization fields in the new PCB
    list_init(&(t->pcb->all_locks));
    list_init(&(t->pcb->all_semaphores));
    lock_init(&(t->pcb->sync_locks));
    lock_init(&(t->pcb->sync_semaphores));
    t->pcb->num_locks = 0;
    t->pcb->num_semaphores = 0;
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);
  }

  /* Temporarily save fpu state in temp, initialize sf->fpu_state for new thread, restore current thread's fpu state*/
  asm volatile("fsave 0(%0); fsave 0(%1); frstor 0(%0)" ::"g"(temp), "g"(if_.fpu_state) : "memory");

  /* Handle failure with successful exit status and PCB malloc.
     Must remove exit status from parent. */
  if (!success && es_success && pcb_success) {
    struct list_elem* removed = list_pop_back(&args->parent_process->child_exit_statuses);
    ASSERT(removed == &t->pcb->exit_status->elem);
  }

  /* Handle failure with successful exit status malloc.
     Must free exit status. */
  if (!success && es_success) {
    free(t->pcb->exit_status);
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;

    // Destroy the user file list and close all associated files
    user_file_list_destroy(&pcb_to_free->user_files);

    free(pcb_to_free);
  }

  /* Set success for parent, and wake parent. */
  args->success = success;
  sema_up(&args->exec_wait);

  /* Exit on failure or jump to userspace */
  if (!success) {
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  /* Get exit status corresponding to child_pid */
  struct list* child_exit_statuses = &thread_current()->pcb->child_exit_statuses;
  struct exit_status* child_exit_status = NULL;
  for (struct list_elem* e = list_begin(child_exit_statuses); e != list_end(child_exit_statuses);
       e = list_next(e)) {
    struct exit_status* ec = list_entry(e, struct exit_status, elem);
    if (ec->pid == child_pid) {
      child_exit_status = ec;
      break;
    }
  }

  /* If exit status not found or already waited on, return -1 */
  if (child_exit_status == NULL || child_exit_status->waited) {
    return -1;
  }

  /* Mark child as waited */
  child_exit_status->waited = true;

  /* If already exited, return exit status */
  if (child_exit_status->exited) {
    return child_exit_status->status;
  }

  /* Otherwise, wait for child to exit and return status */
  sema_down(&child_exit_status->exit_wait);
  return child_exit_status->status;
}

/* Free the current process's resources. */
void process_exit(int status) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  lock_acquire(&cur->pcb->exit_lock);
  lock_acquire(&cur->pcb->pthread_lock);
  cur->pcb->exit = true;
  struct list* user_threads = &cur->pcb->user_threads;
  for (struct list_elem* e = list_begin(user_threads); e != list_end(user_threads);
       e = list_next(e)) {
    struct user_thread* ut = list_entry(e, struct user_thread, elem);
    if (ut->tid == cur->tid) {
      ut->exited = true;
      sema_up(&ut->join_wait);
      break;
    }
  }

  for (struct list_elem* e = list_begin(user_threads); e != list_end(user_threads);
       e = list_next(e)) {
    struct user_thread* ut = list_entry(e, struct user_thread, elem);
    if (!ut->exited && !ut->waited) {
      lock_release(&cur->pcb->pthread_lock);
      sema_down(&ut->join_wait);
      lock_acquire(&cur->pcb->pthread_lock);
    }
  }

  /* Print exit status */
  printf("%s: exit(%d)\n", cur->pcb->process_name, status);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  while (!list_empty(&cur->pcb->child_exit_statuses)) {
    struct list_elem* e = list_pop_front(&cur->pcb->child_exit_statuses);
    struct exit_status* exit_status = list_entry(e, struct exit_status, elem);
    lock_acquire(&exit_status->ref_cnt_lock);
    exit_status->ref_cnt -= 1;
    int ref_cnt = exit_status->ref_cnt;
    lock_release(&exit_status->ref_cnt_lock);
    if (ref_cnt == 0) {
      free(exit_status);
    }
  }

  lock_acquire(&cur->pcb->exit_status->ref_cnt_lock);
  int ref_cnt = cur->pcb->exit_status->ref_cnt -= 1;
  lock_release(&cur->pcb->exit_status->ref_cnt_lock);
  if (ref_cnt == 0) {
    free(cur->pcb->exit_status);
  } else {
    cur->pcb->exit_status->status = status;
    cur->pcb->exit_status->exited = true;
    sema_up(&cur->pcb->exit_status->exit_wait);
  }

  /* Close executable file, allowing write */
  file_close(cur->pcb->exec_file);

  /* Free all user threads */
  while (!list_empty(&cur->pcb->user_threads)) {
    struct list_elem* e = list_pop_front(&cur->pcb->user_threads);
    struct user_thread* ut = list_entry(e, struct user_thread, elem);
    free(ut);
  }

  /* Free user-level synchronization fields in pcb */
  while (!list_empty(&cur->pcb->all_locks)) {
    struct list_elem* e = list_pop_front(&cur->pcb->all_locks);
    struct user_lock* u_lock = list_entry(e, struct user_lock, elem);
    free(u_lock);
  }
  while (!list_empty(&cur->pcb->all_semaphores)) {
    struct list_elem* e = list_pop_front(&cur->pcb->all_semaphores);
    struct user_lock* u_sem = list_entry(e, struct user_semaphore, elem);
    free(u_sem);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;

  // Destroy the user file list and close all associated files
  user_file_list_destroy(&pcb_to_free->user_files);

  free(pcb_to_free);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;

  char *token, *save_ptr;
  char* tokens[MAX_ARGUMENTS];
  int i = 0;

  /* Loops through each token using the builtin strtok_r function and adds it to the list of tokens. */
  for (token = strtok_r((char*)file_name, " ", &save_ptr); token != NULL || i >= MAX_ARGUMENTS;
       token = strtok_r(NULL, " ", &save_ptr)) {
    size_t len = strlen(token) + 1;
    tokens[i] = malloc(len + 1);
    strlcpy(tokens[i], token, MAX_ARGUMENT_SIZE);
    i++;
  }

  strlcpy(t->pcb->process_name, tokens[0], strlen(tokens[0]) + 1);

  /* Save the number of tokens for later. */
  int num_tokens = i;

  /* Addresses used for copying argv onto the stack. 
     This isn't used till later, but since num_tokens is variable it cannot
     come after goto since this is not allowed by C. */
  char* arg_addresses[num_tokens];

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(tokens[0]);
  if (file == NULL) {
    printf("load: %s: open failed\n", tokens[0]);
    goto done;
  }
  t->pcb->exec_file = file;
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", tokens[0]);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Loops through the tokens and adds it to the stack by decrementing
     the stack pointer by the length of the string (including the null
     pointer) and running strcpy to that address. */
  int j;
  for (j = num_tokens - 1; j >= 0; j--) {
    size_t len = strlen(tokens[j]);
    (*((char**)esp)) -= len + 1;
    strlcpy(*((char**)esp), tokens[j], len + 1);

    // Save the argv addresses for when we're adding them to the stack.
    arg_addresses[j] = (*((char**)esp));
  }

  /* Calculate the number of addresses until we reach the bottom of
     the stack after argc. This value is the num_tokens + 1 (includes
     null-valued argv[argc]) + 1 (for the address of argv[0]) + 1 (for
     argc). */
  int rest_of_data = (num_tokens + 3) * 4;

  /* This is the address at which will be the bottom of the stack
     (current - rest_of_data). We make it unsigned so rounding down
     works correctly in the next line. */
  unsigned int target = (unsigned int)((*((char**)esp) - rest_of_data));

  /* We get the size of the stack alignment by getting the difference
     between the target and 16-byte offset, calculated by rounding down
     to be divisible by 16. */
  int stack_align_value = (int)(target - (target / 16 * 16));

  /* Decrement the stack pointer by however many bytes we need to align
     the esp. We also fill these values with 0. */
  *((char**)esp) -= stack_align_value;
  memset(*((char**)esp), 0, stack_align_value);

  /* Per the C Standard, argv[argc] is to be null in order to cause
     out-of-bounds argv reading to immediately cause a
     null-pointer-deference and a segfault. */
  *((char**)esp) -= 4;
  **((char***)esp) = 0;

  /* Fill the addresses for each argument in here (using arg_addresses
     from earlier). */
  for (j = num_tokens - 1; j >= 0; j--) {
    *((char**)esp) -= 4;
    **((char***)esp) = arg_addresses[j];
  }

  /* Now we're adding the arguments to main() to the stack. Here,
     we're adding the address to argv, which is right above this
     address in the stack. */
  *((char**)esp) -= 4;
  **((char****)esp) = *((char***)esp) + 1;

  /* Add argc to the stack. */
  *((char**)esp) -= 4;
  **((int**)esp) = num_tokens;

  /* Add the return address to the stack. This isn't a real return
     address as the entry function doesn't ever return, but it is to be
     consistent across functions. */
  *((char**)esp) -= 4;
  **((void***)esp) = NULL;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if (!success) {
    file_close(file);
  }
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  struct thread* t = thread_current();
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    // Map to first available virtual user page
    uint8_t* page_boundary = (uint8_t*)PHYS_BASE - PGSIZE;
    while (true) {
      if (pagedir_get_page(t->pcb->pagedir, page_boundary) == NULL) {
        success = install_page(page_boundary, kpage, true);
        break;
      }
      page_boundary -= PGSIZE;
    }
    //success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = page_boundary + PGSIZE - 20;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(struct pthread_args* args, void (**eip)(void) UNUSED, void** esp UNUSED) {
  process_activate();
  if (!setup_stack(esp)) {
    return false;
  }
  // Push args->arg and args->tf onto stack with null return address
  *((char**)esp) -= 4;
  **((void***)esp) = args->arg;

  *((char**)esp) -= 4;
  **((pthread_fun***)esp) = args->tf;

  *((char**)esp) -= 4;
  **((void***)esp) = NULL;

  *eip = args->sf;

  return true;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) {
  lock_acquire(&thread_current()->pcb->pthread_lock);
  struct pthread_args* arguments = (struct pthread_args*)malloc(sizeof(struct pthread_args));
  tid_t tid;
  arguments->sf = sf;
  arguments->tf = tf;
  arguments->arg = arg;
  arguments->pcb = thread_current()->pcb;
  sema_init(&(arguments->create_wait), 0);
  tid = thread_create("stub", PRI_DEFAULT, start_pthread, arguments);
  sema_down(&(arguments->create_wait));
  if (!arguments->success) {
    tid = TID_ERROR;
  }
  free(arguments);
  lock_release(&thread_current()->pcb->pthread_lock);
  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {
  struct intr_frame if_;
  struct pthread_args* args = (struct pthread_args*)exec_;
  struct thread* t = thread_current();
  t->pcb = args->pcb;

  struct user_thread* u_thread = (struct user_thread*)malloc(sizeof(struct user_thread));
  if (u_thread == NULL) {
    args->success = false;
    return;
  }
  u_thread->tid = t->tid;
  u_thread->exited = false;
  u_thread->waited = false;
  sema_init(&(u_thread->join_wait), 0);
  list_push_back(&t->pcb->user_threads, &u_thread->elem);

  /* Set interrupt frame flags, copied from start_process() */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  bool success = setup_thread(args, &if_.eip, &if_.esp);

  if (!success) {
    // Free u_thread and remove from list
    struct list_elem* removed = list_pop_back(&t->pcb->user_threads);
    ASSERT(removed == &u_thread->elem);
    free(u_thread);
  } else {
    u_thread->stack = pg_round_down(if_.esp);
  }
  args->success = success;
  sema_up(&args->create_wait);

  if (!success) {
    pthread_exit();
  }

  /* Simulate a return from an interrupt to start user_thread running */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) {
  lock_acquire(&thread_current()->pcb->pthread_lock);
  // Check for self-join
  if (tid == thread_current()->tid) {
    lock_release(&thread_current()->pcb->pthread_lock);
    return TID_ERROR;
  }

  struct list* user_threads = &thread_current()->pcb->user_threads;
  struct user_thread* ut;
  for (struct list_elem* e = list_begin(user_threads); e != list_end(user_threads);
       e = list_next(e)) {
    ut = list_entry(e, struct user_thread, elem);
    if (ut->tid == tid) {
      if (ut->exited && !ut->waited) {
        lock_release(&thread_current()->pcb->pthread_lock);
        return ut->tid;
      } else if (!ut->waited) {
        ut->waited = true;
        lock_release(&thread_current()->pcb->pthread_lock);
        sema_down(&ut->join_wait);
        lock_acquire(&thread_current()->pcb->pthread_lock);
        list_remove(&ut->elem);
        free(ut);
        lock_release(&thread_current()->pcb->pthread_lock);
        return tid;
      }
      break;
    }
  }

  lock_release(&thread_current()->pcb->pthread_lock);
  return TID_ERROR;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* t = thread_current();
  lock_acquire(&t->pcb->pthread_lock);

  struct list* user_threads = &t->pcb->user_threads;
  for (struct list_elem* e = list_begin(user_threads); e != list_end(user_threads);
       e = list_next(e)) {
    struct user_thread* ut = list_entry(e, struct user_thread, elem);
    if (ut->tid == t->tid) {
      ut->exited = true;
      // Free user thread stack and free struct user_thread if waited if true?
      uint8_t* kpage = pagedir_get_page(t->pcb->pagedir, ut->stack);
      if (kpage != NULL) {
        palloc_free_page(kpage);
      }
      pagedir_clear_page(t->pcb->pagedir, ut->stack);

      sema_up(&ut->join_wait);
      lock_release(&t->pcb->pthread_lock);
      thread_exit();
    }
  }
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  struct thread* t = thread_current();
  lock_acquire(&t->pcb->pthread_lock);

  struct list* user_threads = &t->pcb->user_threads;
  // Main thread should be at front of list
  struct list_elem* e = list_front(user_threads);
  struct user_thread* ut_main = list_entry(e, struct user_thread, elem);
  ut_main->exited = true;
  sema_up(&ut_main->join_wait);
  // Free user thread stack and free struct user_thread if waited if true?
  // uint8_t* kpage = pagedir_get_page(t->pcb->pagedir, (uint8_t*)PHYS_BASE - PGSIZE);
  // if (kpage != NULL) {
  //   palloc_free_page(kpage);
  // }
  // pagedir_clear_page(t->pcb->pagedir, (uint8_t*)PHYS_BASE - PGSIZE);

  for (struct list_elem* e = list_begin(user_threads); e != list_end(user_threads);
       e = list_next(e)) {
    struct user_thread* ut = list_entry(e, struct user_thread, elem);
    if (!ut->exited && !ut->waited) {
      lock_release(&t->pcb->pthread_lock);
      sema_down(&ut->join_wait);
      lock_acquire(&t->pcb->pthread_lock);
    }
  }
  lock_release(&t->pcb->pthread_lock);
  process_exit(0);
}

void pthread_exit_trap(void) {
  struct thread* t = thread_current();
  if (t->pcb->exit) {
    pthread_exit();
  }
}