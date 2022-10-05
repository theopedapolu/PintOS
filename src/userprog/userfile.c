#include "userprog/userfile.h"

/* Opens a file given a file path and list to add it to.
   This creates a new entry in the list and assigns it a
   file descriptor. */
int user_file_open(user_file_list* list, const char* file, int fd) {}

/* Closes a file in the list given a file descriptor.
   This includes removing the user_file entry within
   the list and frees all the necessary components. */
void user_file_close(user_file_list* list, int fd) {}

/* Returns the user_file struct from the user_file_list
   with the corresponding file descriptor supplied. 
   If the file descriptor is not present in the list,
   returns NULL. */
struct user_file* user_file_get(user_file_list* list, int fd) {}