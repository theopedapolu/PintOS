/* Tests the buffer cache’s effectiveness by measuring
   its cache hit rate. */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

/* 16 KiB, half of the size of the cache */
#define TEST_SIZE 16384

static const char* file_name = "hitrate";
static char buf[TEST_SIZE];

void test_main(void) {
  int fd;
  double cold_hit_rate, re_hit_rate;

  /* Create, open, and write file of size TEST_SIZE */
  random_bytes(buf, TEST_SIZE);
  CHECK(create(file_name, TEST_SIZE), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  CHECK(write(fd, buf, TEST_SIZE) == TEST_SIZE, "write \"%s\"", file_name);
  msg("close \"%s\"", file_name);
  close(fd);

  /* Get hit rate on cold read */
  buffer_cache_reset();
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  CHECK(read(fd, buf, TEST_SIZE) == TEST_SIZE, "read \"%s\"", file_name);
  msg("close \"%s\"", file_name);
  close(fd);
  cold_hit_rate = buffer_cache_hit_rate();

  /* Get hit rate on reread */
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  CHECK(read(fd, buf, TEST_SIZE) == TEST_SIZE, "read \"%s\"", file_name);
  msg("close \"%s\"", file_name);
  close(fd);
  re_hit_rate = buffer_cache_hit_rate();

  /* Compare hit rates */
  if (re_hit_rate > cold_hit_rate) {
    msg("reread hit rate greater than cold hit rate");
  } else {
    fail("reread hit rate (%f) less than cold hit rate (%f)", re_hit_rate, cold_hit_rate);
  }
}
