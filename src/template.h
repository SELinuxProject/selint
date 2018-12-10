#ifndef TEMPLATE_H
#define TEMPLATE_H

// Functions for dealing with declarations in templates

#include "tree.h"

/* Replace bash style arguments with a string */
char *replace_m4(char *orig, struct string_list *args);

#endif
