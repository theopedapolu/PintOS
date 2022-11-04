/* Verifies that sema_up considers effective priority
   over base priority when choosing which thread to
   put back on the ready queue. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/synch.h"

static thread_func effective_priority_thread;
static thread_func donator_thread;
static thread_func base_priority_thread;

struct semaphore sem;
struct lock loc;

void test_priority_donate_sema_2(void) {
  /* This test does not work with the MLFQS. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  /* Make sure our priority is the default. */
  ASSERT(thread_get_priority() == PRI_DEFAULT);

  msg("Initializing lock.");
  sema_init(&sem, 0);
  msg("Initializing semaphore to 0.");
  lock_init(&loc);

  msg("Creating a low priority thread.");
  thread_create("low", PRI_DEFAULT + 1, effective_priority_thread, NULL);
  msg("Creating a high priority thread.");
  thread_create("high", PRI_DEFAULT + 3, donator_thread, NULL);
  msg("Creating a medium priority thread.");
  thread_create("medium", PRI_DEFAULT + 2, base_priority_thread, NULL);

  msg("Upping semaphore.");
  sema_up(&sem);
}

static void effective_priority_thread(void* aux UNUSED) {
  msg("Low priority thread now acquiring lock.");
  lock_acquire(&loc);
  msg("Low priority thread now downing semaphore.");
  sema_down(&sem);
  msg("Low priority thread now releasing lock.");
  lock_release(&loc);
  msg("Low priority thread now upping semaphore.");
  sema_up(&sem);
  msg("Low priority thread exiting.");
}

static void donator_thread(void* aux UNUSED) {
  msg("High priority thread waiting to acquire lock.");
  lock_acquire(&loc);
  msg("High priority thread now releasing lock.");
  lock_release(&loc);
  msg("High priority thread exiting.");
}

static void base_priority_thread(void* aux UNUSED) {
  msg("Medium priority thread now downing semaphore.");
  sema_down(&sem);
  msg("Medium priority thread now upping semaphore.");
  sema_up(&sem);
  msg("Medium priority thread now exiting.");
}
