#include "filesys/cache.h"
#include <debug.h>
#include "threads/synch.h"

/* Number of entries in the cache. */
#define CACHE_SIZE 64

/* Entry in the cache with both metadata and data contained
   in the corresponding block. */
struct cache_entry {
  block_sector_t sector;           /* Cache tag. */
  bool valid;                      /* True if data valid. */
  bool dirty;                      /* True if data should be written back on eviction. */
  uint64_t last_accessed;          /* Ticks of last access. */
  int num_accessing;               /* Number of threads trying to access data. */
  struct condition valid_wait;     /* Wait for valid data. */
  struct lock data_lock;           /* Lock on data. */
  uint8_t data[BLOCK_SECTOR_SIZE]; /* Data on disk. */
};

/* Buffer cache entries. */
struct cache_entry buffer_cache[CACHE_SIZE];

/* Global lock on buffer_cache metadata. */
struct lock cache_lock;

/* Initializes the buffer cache module. */
void cache_init(void) {
  for (int i = 0; i < CACHE_SIZE; i++) {
    buffer_cache[i].dirty = false;
    buffer_cache[i].last_accessed = 0;
    buffer_cache[i].num_accessing = 0;
    cond_init(&buffer_cache[i].valid_wait);
    lock_init(&buffer_cache[i].data_lock);
  }
  lock_init(&cache_lock);
}

/* Reads the contents of SECTOR into BUFFER via the cache. */
void cache_read(block_sector_t sector UNUSED, void* buffer UNUSED) { return; }

/* Writes BUFFER into SECTOR via the cache. */
void cache_write(block_sector_t sector UNUSED, void* buffer UNUSED) { return; }

/* Returns the data buffer in the cache entry corresponding
   to SECTOR. Can be called only by one thread at a time. */
void* cache_get_buffer(block_sector_t sector UNUSED) { return NULL; }

/* Releases BUFFER returned by cache_get_buffer to be used
   by another thread. */
void cache_release_buffer(void* buffer UNUSED) { return; }

/* Flushes all blocks in the cache to disk.
   Called in function filesys_done in filesys/filesys.c. */
void cache_flush(void) { return; }
