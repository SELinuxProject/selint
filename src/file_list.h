#ifndef FILE_LIST_H
#define FILE_LIST_H

#include "tree.h"

struct policy_file {
	char *filename;
	char *mod_name;
	struct policy_node *ast;
};

struct policy_file_node {
	struct policy_file *file;
	struct policy_file_node *next;
};

struct policy_file_list {
	struct policy_file_node *head;
	struct policy_file_node *tail;
};

void file_list_push_back(struct policy_file_list *list, struct policy_file *file);

struct policy_file * make_policy_file(char *filename, struct policy_node *ast);

void free_file_list(struct policy_file_list *to_free);

#endif
