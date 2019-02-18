#ifndef STRING_LIST_H
#define STRING_LIST_H

struct string_list {
	char *string;
	struct string_list *next;
	int has_incorrect_space;
};

int str_in_sl(const char *str, struct string_list *sl);

void free_string_list(struct string_list *list);

#endif
