#ifndef USERPROG_USERFILE_H
#define USERPROG_USERFILE_H

#include <list.h>

struct user_file {
  int fd;
  struct file* file;
  struct list_elem elem;
};

struct user_dir {
  int fd;
  struct dir* directory;
  struct list_elem elem;
};

typedef struct list user_file_list;

int user_file_open(user_file_list* list, const char* file, int fd);
void user_file_close(user_file_list* list, int fd);
struct user_file* user_file_get(user_file_list* list, int fd);
void user_file_list_destroy(user_file_list* list);

#endif /* userprog/userfile.h */
