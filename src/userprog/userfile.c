#include "userprog/userfile.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"

/* Opens a file given a file path and list to add it to.
   This creates a new entry in the list and assigns it a
   file descriptor. */
void user_file_open(user_file_list* list, const char* file, int fd) {
  struct file* f = filesys_open(file);
  struct user_file* uf = malloc(sizeof(struct user_file));

  uf->file = f;
  uf->fd = fd;

  list_push_back(list, &uf->elem);
}

/* Closes a file in the list given a file descriptor.
   This includes removing the user_file entry within
   the list and frees all the necessary components. */
void user_file_close(user_file_list* list, int fd) {
  struct list_elem* e;
  for (e = list_begin(list); e != list_end(list); e = list_next(e)) {
    struct user_file* f = list_entry(e, struct user_file, elem);

    if (f->fd == fd) {
      list_remove(e);
      file_close(f->file);
      free(f);
      break;
    }
  }
}

/* Returns the user_file struct from the user_file_list
   with the corresponding file descriptor supplied. 
   If the file descriptor is not present in the list,
   returns NULL. */
struct user_file* user_file_get(user_file_list* list, int fd) {
  struct list_elem* e;
  for (e = list_begin(list); e != list_end(list); e = list_next(e)) {
    struct user_file* f = list_entry(e, struct user_file, elem);

    if (f->fd == fd) {
      return f;
    }
  }

  return NULL;
}

/* Destroys this user_file_list, closing all files
   associating with the list and freeing their respective
   entries. */
void user_file_list_destroy(user_file_list* list) {
  while (!list_empty(list)) {
    struct list_elem* e = list_pop_front(list);
    struct user_file* f = list_entry(e, struct user_file, elem);

    file_close(f->file);
    free(f);
  }
}
