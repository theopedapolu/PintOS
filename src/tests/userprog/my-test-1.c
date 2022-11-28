/* Invokes a system call with an invalid system call number.
   The process must be terminated with -1 exit code. */

#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  asm volatile("pushl $0x23; int $0x30");
  fail("should have killed process");
}
