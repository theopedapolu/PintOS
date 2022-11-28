/* Test the buffer cache’s ability to coalesce writes
   to the same sector. */

#include <random.h>
#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

/* 64 KiB, twice the size of the cache */
#define TEST_SIZE 65536

static const char* file_name = "coalesce";
static char buf[TEST_SIZE];

void test_main(void) {
  int fd;
  int start_write_cnt = filesys_writes();

  /* Create and open file of size TEST_SIZE */
  random_bytes(buf, TEST_SIZE);
  CHECK(create(file_name, TEST_SIZE), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);

  /* Write file byte by byte and get write_cnt */
  msg("writing \"%s\"", file_name);
  for (size_t ofs = 0; ofs < TEST_SIZE; ofs++) {
    if (write(fd, buf + ofs, 1) != 1) {
      fail("write byte at offset %zu in \"%s\" failed", ofs, file_name);
    }
  }
  msg("close \"%s\"", file_name);
  close(fd);

  /* Read file byte by byte and get read_cnt */
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  for (size_t ofs = 0; ofs < TEST_SIZE; ofs++) {
    char read_buf;
    if (read(fd, &read_buf, 1) != 1)
      fail("read byte at offset %zu in \"%s\" failed", ofs, file_name);
    if (read_buf != buf[ofs])
      fail("value read at offset %zu in \"%s\" incorrect", ofs, file_name);
  }
  msg("close \"%s\"", file_name);
  close(fd);

  /* write_cnt should be on the order of 128 since 64 KiB is 128 blocks */
  int write_cnt = filesys_writes() - start_write_cnt;
  if (write_cnt < 1024) {
    msg("write count on the order of 128");
  } else {
    fail("write count of %d not on the order of 128", write_cnt);
  }
}
