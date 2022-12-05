#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"

/* Number of direct pointers in an inode. */
#define NUM_DIRECT_POINTERS 124

/* Number of sector pointers that can be stored in a block. */
#define POINTERS_PER_BLOCK 128

/* Maximum file size using just direct pointers. */
static const off_t DIRECT_CAPACITY = NUM_DIRECT_POINTERS * BLOCK_SECTOR_SIZE;

/* Added file capacity of indirect pointer. */
static const off_t INDIRECT_CAPACITY = POINTERS_PER_BLOCK * BLOCK_SECTOR_SIZE;

/* Added file capacity of doubly indirect pointer. */
static const off_t DOUBLY_INDIRECT_CAPACITY =
    POINTERS_PER_BLOCK * POINTERS_PER_BLOCK * BLOCK_SECTOR_SIZE;

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  bool is_dir;                                /* True if this inode represents a directory. */
  block_sector_t direct[NUM_DIRECT_POINTERS]; /* Direct pointers. */
  block_sector_t indirect;                    /* Indirect pointer. */
  block_sector_t doubly_indirect;             /* Doubly indirect pointer. */
  off_t length;                               /* File size in bytes. */
  uint8_t unused[3];                          /* Not used. */
  unsigned magic;                             /* Magic number. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;    /* Element in inode list. */
  block_sector_t sector;    /* Sector number of disk location. */
  int open_cnt;             /* Number of openers. */
  bool removed;             /* True if deleted, false otherwise. */
  int deny_write_cnt;       /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock;   /* Lock on removed and deny_write_cnt. */
  struct rw_lock data_lock; /* R: reads and writes, W: extensions. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  block_sector_t sector = -1;
  struct inode_disk* inode_data = cache_get_buffer(inode->sector, true);

  /* No data at offsets greater than or equal to length */
  if (pos >= inode_data->length) {
    cache_release_buffer(inode_data, false, false);
    return sector;
  }

  if (pos < DIRECT_CAPACITY) {
    sector = inode_data->direct[pos / BLOCK_SECTOR_SIZE];
  } else if (pos < DIRECT_CAPACITY + INDIRECT_CAPACITY) {
    ASSERT(inode_data->indirect != 0);
    block_sector_t* indirect_data = cache_get_buffer(inode_data->indirect, true);
    sector = indirect_data[(pos - DIRECT_CAPACITY) / BLOCK_SECTOR_SIZE];
    cache_release_buffer(indirect_data, false, false);
  } else if (pos < DIRECT_CAPACITY + INDIRECT_CAPACITY + DOUBLY_INDIRECT_CAPACITY) {
    ASSERT(inode_data->doubly_indirect != 0);
    block_sector_t* doubly_indirect_data = cache_get_buffer(inode_data->doubly_indirect, true);
    int indirect_index = (pos - DIRECT_CAPACITY - INDIRECT_CAPACITY) / INDIRECT_CAPACITY;
    ASSERT(doubly_indirect_data[indirect_index] != 0);
    block_sector_t* indirect_data = cache_get_buffer(doubly_indirect_data[indirect_index], true);
    sector = indirect_data[(pos - DIRECT_CAPACITY - INDIRECT_CAPACITY -
                            indirect_index * INDIRECT_CAPACITY) /
                           BLOCK_SECTOR_SIZE];
    cache_release_buffer(indirect_data, false, false);
    cache_release_buffer(doubly_indirect_data, false, false);
  }

  cache_release_buffer(inode_data, false, false);
  return sector;
}

/* Zeros the sector SECTOR. */
static void zero_sector(block_sector_t sector) {
  void* data = cache_get_buffer(sector, false);
  memset(data, 0, BLOCK_SECTOR_SIZE);
  cache_release_buffer(data, true, true);
}

/* Resizes INODE_DATA to have length SIZE by modifying its direct,
   indirect, and doubly indirect pointers and allocating and
   deallocating blocks on disk. */
static bool inode_disk_resize(struct inode_disk* inode_data, off_t size) {
  ASSERT(inode_data != NULL);
  bool success = true;

  /* Handle direct pointers */
  for (int i = 0; i < NUM_DIRECT_POINTERS; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && inode_data->direct[i] != 0) {
      /* Shrink */
      free_map_release(inode_data->direct[i], 1);
      inode_data->direct[i] = 0;
    } else if (size > i * BLOCK_SECTOR_SIZE && inode_data->direct[i] == 0) {
      /* Grow */
      if (!free_map_allocate(1, &inode_data->direct[i])) {
        success = false;
        goto done;
      }
      zero_sector(inode_data->direct[i]);
    }
  }

  /* Allocate indirect block if required */
  if (inode_data->indirect == 0) {
    /* Indirect pointers not needed */
    if (size <= DIRECT_CAPACITY) {
      goto doubly_indirect;
    }
    if (!free_map_allocate(1, &inode_data->indirect)) {
      success = false;
      goto done;
    }
    zero_sector(inode_data->indirect);
  }
  /* Handle indirect pointers */
  block_sector_t* indirect_data = cache_get_buffer(inode_data->indirect, true);
  for (int i = 0; i < POINTERS_PER_BLOCK; i++) {
    if (size <= DIRECT_CAPACITY + i * BLOCK_SECTOR_SIZE && indirect_data[i] != 0) {
      /* Shrink */
      free_map_release(indirect_data[i], 1);
      indirect_data[i] = 0;
    } else if (size > DIRECT_CAPACITY + i * BLOCK_SECTOR_SIZE && indirect_data[i] == 0) {
      /* Grow */
      if (!free_map_allocate(1, &indirect_data[i])) {
        success = false;
        goto done;
      }
      zero_sector(indirect_data[i]);
    }
  }
  if (size <= DIRECT_CAPACITY) {
    /* We shrank the inode such that indirect pointers are not required */
    cache_release_buffer(indirect_data, false, false);
    free_map_release(inode_data->indirect, 1);
    inode_data->indirect = 0;
  } else {
    /* Write the updates to the indirect block back to disk */
    cache_release_buffer(indirect_data, false, true);
  }

doubly_indirect:
  /* Allocate doubly indirect block if required */
  if (inode_data->doubly_indirect == 0) {
    /* Doubly indirect pointers not needed */
    if (size <= DIRECT_CAPACITY + INDIRECT_CAPACITY) {
      goto done;
    }
    if (!free_map_allocate(1, &inode_data->doubly_indirect)) {
      success = false;
      goto done;
    }
    zero_sector(inode_data->doubly_indirect);
  }
  /* Handle doubly indirect pointers */
  block_sector_t* doubly_indirect_data = cache_get_buffer(inode_data->doubly_indirect, true);
  /* Traverse doubly indirect block */
  for (int i = 0; i < POINTERS_PER_BLOCK; i++) {
    /* Allocate indirect block if required */
    if (doubly_indirect_data[i] == 0) {
      /* This indirect block not needed */
      if (size <= DIRECT_CAPACITY + (i + 1) * INDIRECT_CAPACITY) {
        continue;
      }
      if (!free_map_allocate(1, &doubly_indirect_data[i])) {
        success = false;
        goto done;
      }
      zero_sector(doubly_indirect_data[i]);
    }
    /* Traverse indirect block */
    indirect_data = cache_get_buffer(doubly_indirect_data[i], true);
    for (int j = 0; j < POINTERS_PER_BLOCK; j++) {
      if (size <= DIRECT_CAPACITY + (i + 1) * INDIRECT_CAPACITY + j * BLOCK_SECTOR_SIZE &&
          indirect_data[j] != 0) {
        /* Shrink */
        free_map_release(indirect_data[j], 1);
        indirect_data[j] = 0;
      } else if (size > DIRECT_CAPACITY + (i + 1) * INDIRECT_CAPACITY + j * BLOCK_SECTOR_SIZE &&
                 indirect_data[j] == 0) {
        /* Grow */
        if (!free_map_allocate(1, &indirect_data[j])) {
          success = false;
          goto done;
        }
        zero_sector(indirect_data[j]);
      }
    }
    if (size <= DIRECT_CAPACITY + INDIRECT_CAPACITY + i * INDIRECT_CAPACITY) {
      /* We shrank the inode such that this direct block is not required */
      cache_release_buffer(indirect_data, false, false);
      free_map_release(doubly_indirect_data[i], 1);
      doubly_indirect_data[i] = 0;
    } else {
      /* Write the updates to this direct block back to disk */
      cache_release_buffer(indirect_data, false, true);
    }
  }
  if (size <= DIRECT_CAPACITY + INDIRECT_CAPACITY) {
    /* We shrank the inode such that doubly indirect pointers are not required */
    cache_release_buffer(doubly_indirect_data, false, false);
    free_map_release(inode_data->doubly_indirect, 1);
    inode_data->doubly_indirect = 0;
  } else {
    /* Writes the updates to the doubly indirect block back to disk */
    cache_release_buffer(doubly_indirect_data, false, true);
  }

done:
  if (!success) {
    inode_disk_resize(inode_data, inode_data->length);
  } else {
    inode_data->length = size;
  }
  return success;
}

static bool inode_resize(const struct inode* inode, off_t size) {
  struct inode_disk* inode_data = cache_get_buffer(inode->sector, true);
  bool success = inode_disk_resize(inode_data, size);
  cache_release_buffer(inode_data, false, success);
  return success;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Lock on open_inodes and open_cnt in struct inode. */
static struct lock open_inodes_lock;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&open_inodes_lock);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device. Creates a directory if IS_DIR is true.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  ASSERT(length >= 0);

  struct inode_disk* disk_inode = cache_get_buffer(sector, false);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode->is_dir = is_dir;
  disk_inode->length = length;
  disk_inode->magic = INODE_MAGIC;
  for (int i = 0; i < NUM_DIRECT_POINTERS; i++) {
    disk_inode->direct[i] = 0;
  }
  disk_inode->indirect = 0;
  disk_inode->doubly_indirect = 0;
  bool success = inode_disk_resize(disk_inode, length);

  cache_release_buffer(disk_inode, true, success);

  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode = NULL;

  /* Check whether this inode is already open. */
  lock_acquire(&open_inodes_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode->open_cnt += 1;
      lock_release(&open_inodes_lock);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL) {
    lock_release(&open_inodes_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);
  rw_lock_init(&inode->data_lock);

  lock_release(&open_inodes_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&open_inodes_lock);
    inode->open_cnt++;
    lock_release(&open_inodes_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&open_inodes_lock);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      struct inode_disk* data = cache_get_buffer(inode->sector, true);
      inode_disk_resize(data, 0);
      cache_release_buffer(data, false, false);
    }

    free(inode);
  }

  lock_release(&open_inodes_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->inode_lock);
  inode->removed = true;
  lock_release(&inode->inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  rw_lock_acquire(&inode->data_lock, RW_READER);

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    if (sector_idx == (block_sector_t)-1) {
      break;
    }
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      uint8_t* bounce = cache_get_buffer(sector_idx, true);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
      cache_release_buffer(bounce, false, false);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  rw_lock_release(&inode->data_lock, RW_READER);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  lock_acquire(&inode->inode_lock);
  int deny_write_cnt = inode->deny_write_cnt;
  lock_release(&inode->inode_lock);
  if (deny_write_cnt)
    return 0;

  /* Grow: acquire R, Don't grow: acquire W */
  bool grow = inode_length(inode) < offset + size;
  rw_lock_acquire(&inode->data_lock, !grow);

  /* Grow if still required after acquiring lock */
  if (inode_length(inode) < offset + size) {
    /* Return if resize fails */
    if (!inode_resize(inode, offset + size)) {
      rw_lock_release(&inode->data_lock, RW_WRITER);
    }
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    if (sector_idx == (block_sector_t)-1) {
      break;
    }
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(sector_idx, buffer + bytes_written);
    } else {
      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      uint8_t* bounce = cache_get_buffer(sector_idx, true);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_release_buffer(bounce, false, true);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  /* Release appropriate lock. */
  rw_lock_release(&inode->data_lock, !grow);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk* data = cache_get_buffer(inode->sector, true);
  off_t length = data->length;
  cache_release_buffer(data, false, false);
  return length;
}
