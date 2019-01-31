#include <stdlib.h>

#include "string_list.h"

void free_string_list(struct string_list *list) {
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


