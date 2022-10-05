#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

// Command line argument limits
#define MAX_ARGUMENTS 32
#define MAX_ARGUMENT_SIZE 64

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* A process's exit status. The PCB for each process contains a
   pointer to its exit status, and a list of its children's exit
   statuses. */
struct exit_status {
  pid_t pid;                  /* Process id */
  int status;                 /* Exit status */
  bool exited;                /* True if exited, false otherwise */
  int ref_cnt;                /* Initialize to 2 */
  struct lock ref_cnt_lock;   /* Lock for ref_cnt */
  struct semaphore exit_wait; /* Down'd by parent's process_wait, up'd by process_exit */
  struct list_elem elem;      /* List element for PCB's child_exit_statuses */
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;               /* Page directory. */
  char process_name[16];           /* Name of the main thread */
  struct thread* main_thread;      /* Pointer to main thread */
  struct exit_status* exit_status; /* Point to this process's exit status */
  struct list child_exit_statuses; /* List of children's exit statuses */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int status);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
