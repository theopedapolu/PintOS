#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include <stdbool.h>

void cache_init(void);
void cache_read(block_sector_t, void*);
void cache_write(block_sector_t, const void*);
void* cache_get_buffer(block_sector_t, bool read_on_miss);
void cache_release_buffer(void*, bool validated, bool dirtied);
void cache_flush(void);

#endif /* filesys/cache.h */
