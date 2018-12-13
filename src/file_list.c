#include <stdlib.h>

#include "file_list.h"

void file_list_push_back(struct policy_file_list *list, struct policy_file *file) {

	if (list->tail) {
		list->tail->next = malloc(sizeof(struct policy_file_node));
		list->tail = list->tail->next;
	} else {
		list->head = list->tail = malloc(sizeof(struct policy_file_node));
	}
	list->tail->file = file;
	list->tail->next = NULL;
}

struct policy_file * make_policy_file(char *filename, struct policy_node *ast) {
	struct policy_file *ret = malloc(sizeof(struct policy_node));
	ret->filename = strdup(filename);
	ret->ast = ast;
	return ret;
}

void free_file_list(struct policy_file_list *to_free) {
	struct policy_file_node *cur = to_free->head;
	while (cur) {
		free(cur->file->filename);
		free_policy_node(cur->file->ast);
		free(cur->file);
		struct policy_node *tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	free(to_free);
}

