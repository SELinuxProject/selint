#ifndef STRING_LIST_H
#define STRING_LIST_H

struct string_list {
	char *string;
	struct string_list *next;
};

void free_string_list(struct string_list *list);

#endif
