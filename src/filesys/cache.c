#include "filesys/cache.h"
#include <debug.h>
#include <string.h>
#include "devices/timer.h"
#include "filesys/filesys.h"
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
  int num_accessing;               /* Number of threads trying to access. Do not evict if >0. */
  struct condition valid_wait;     /* Wait for valid data. Used with cache_lock. */
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

/* Returns a pointer to an entry in buffer_cache matching SECTOR
   or the entry to evict based on LRU.
   Set READ_ON_MISS to true if the data in SECTOR should be read
   into the entry on a cache miss (i.e., READ_ON_MISS can be set
   to false on a blind write). */
static struct cache_entry* cache_get_entry(block_sector_t sector, bool read_on_miss) {
  struct cache_entry* entry = NULL;
  lock_acquire(&cache_lock);

  for (int i = 0; i < CACHE_SIZE; i++) {
    /* Cache hit */
    if (buffer_cache[i].sector == sector) {
      buffer_cache[i].num_accessing += 1;
      if (!buffer_cache[i].valid) {
        cond_wait(&buffer_cache[i].valid_wait, &cache_lock);
      }
      entry = &buffer_cache[i];
      break;
    }
    /* No hit yet, track entry to evict by LRU */
    if (buffer_cache[i].num_accessing == 0 &&
        (entry == NULL || buffer_cache[i].last_accessed < entry->last_accessed)) {
      entry = &buffer_cache[i];
    }
  }

  /* On miss, while holding cache_lock, invalidate the entry */
  block_sector_t old_sector = entry->sector;
  if (old_sector != sector) {
    entry->sector = sector;
    entry->valid = false;
    entry->num_accessing += 1;
  }

  ASSERT(entry->num_accessing >= 1);

  lock_release(&cache_lock);

  if (old_sector != sector) {
    /* On miss, while holding data_lock, write back data if dirty
       and read in data if specified */
    lock_acquire(&entry->data_lock);
    if (entry->dirty) {
      block_write(fs_device, old_sector, entry->data);
    }
    if (read_on_miss) {
      block_read(fs_device, sector, entry->data);
    }
    lock_release(&entry->data_lock);

    /* On miss, while holding cache_lock, update entry's metadata
       and validate data if new data was read in */
    lock_acquire(&cache_lock);
    entry->dirty = false;
    if (read_on_miss) {
      entry->valid = true;
      cond_broadcast(&entry->valid_wait, &cache_lock);
    }
    lock_release(&cache_lock);
  }

  return entry;
}

/* Releases ENTRY to be used by another thread.
   Set VALID to true if the data in ENTRY is valid
   and set DIRTY to true if this entry was written to. */
static void cache_release_entry(struct cache_entry* entry, bool valid, bool dirty) {
  lock_acquire(&cache_lock);
  ASSERT(entry->num_accessing >= 1);

  if (!entry->valid && valid) {
    cond_broadcast(&entry->valid_wait, &cache_lock);
  }
  entry->valid = valid;
  entry->dirty = dirty;
  entry->last_accessed = timer_ticks();
  entry->num_accessing -= 1;

  lock_release(&cache_lock);
}

/* Reads the contents of SECTOR into BUFFER via the cache.
   BUFFER should have size BLOCK_SECTOR_SIZE. */
void cache_read(block_sector_t sector, void* buffer) {
  struct cache_entry* entry = cache_get_entry(sector, true);
  lock_acquire(&entry->data_lock);
  memcpy(buffer, entry->data, BLOCK_SECTOR_SIZE);
  lock_release(&entry->data_lock);
  cache_release_entry(entry, true, false);
}

/* Writes BUFFER into SECTOR via the cache.
   BUFFER should have size BLOCK_SECTOR_SIZE. */
void cache_write(block_sector_t sector, void* buffer) {
  struct cache_entry* entry = cache_get_entry(sector, false);
  lock_acquire(&entry->data_lock);
  memcpy(entry->data, buffer, BLOCK_SECTOR_SIZE);
  lock_release(&entry->data_lock);
  cache_release_entry(entry, true, true);
}

/* Returns the data buffer in the cache entry corresponding
   to SECTOR. Can be called only by one thread at a time. */
void* cache_get_buffer(block_sector_t sector UNUSED) { return NULL; }

/* Releases BUFFER returned by cache_get_buffer to be used
   by another thread. */
void cache_release_buffer(void* buffer UNUSED) { return; }

/* Flushes all blocks in the cache to disk.
   Called in function filesys_done in filesys/filesys.c. */
void cache_flush(void) { return; }
