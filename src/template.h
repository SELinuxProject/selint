#ifndef TEMPLATE_H
#define TEMPLATE_H

// Functions for dealing with declarations in templates

#include "selint_error.h"
#include "tree.h"

/* Replace bash style arguments with a string */
char *replace_m4(char *orig, struct string_list *args);

/* Loop over replace_from string_list and call replace_m4 on each string in it, using the
 * strings in replace_with as the arguments. */
struct string_list *replace_m4_list(struct string_list *replace_with,
				    struct string_list *replace_from);

enum selint_error add_template_declarations(char *template_name,
					    struct string_list *args,
					    struct string_list
					    *parent_temp_names, char *mod_name);

#endif
