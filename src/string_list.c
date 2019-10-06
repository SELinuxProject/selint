#include <stdlib.h>
#include <string.h>

#include "string_list.h"
int str_in_sl(const char *str, struct string_list *sl)
{

	if (!sl) {
		return 0;
	}

	while (sl) {
		if (0 == strcmp(sl->string, str)) {
			return 1;
		}
		sl = sl->next;
	}
	return 0;
}

struct string_list *copy_string_list(struct string_list *sl)
{
	if (!sl) {
		return NULL;
	}
	struct string_list *ret = malloc(sizeof(struct string_list));
	struct string_list *cur = ret;

	while (sl) {
		cur->string = strdup(sl->string);
		cur->has_incorrect_space = sl->has_incorrect_space;

		if (sl->next) {
			cur->next = malloc(sizeof(struct string_list));
		} else {
			cur->next = NULL;
		}
		sl = sl->next;
		cur = cur->next;
	}
	return ret;
}

void free_string_list(struct string_list *list)
{
	if (list == NULL) {
		return;
	}
	struct string_list *cur = list;

	while (cur) {
		struct string_list *to_free = cur;
		cur = cur->next;
		free(to_free->string);
		free(to_free);
	}
}
