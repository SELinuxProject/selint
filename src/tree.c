#include <stddef.h>
#include <stdlib.h>

#include "tree.h"
#include "selint_error.h"

enum selint_error insert_policy_node(struct policy_node *parent,
				enum node_flavor flavor,
				union node_data data) {

	if (parent == NULL || ( (data.av == NULL) && (data.m4_name == NULL) && (data.string == NULL) )) {
		return SELINT_BAD_ARG;
	}

	struct policy_node *to_insert = malloc(sizeof(struct policy_node));

	to_insert->parent = parent;
	to_insert->next = NULL;
	to_insert->first_child = NULL;
	to_insert->flavor = flavor;
	to_insert->data = data;

	if (parent->first_child == NULL) {
		parent->first_child = to_insert;
		to_insert->prev = NULL;
	} else {

		struct policy_node *cur = parent->first_child;

		while (cur->next != NULL) {
			cur = cur->next;
		}

		cur->next = to_insert;
		to_insert->prev = cur;

	}

	return SELINT_SUCCESS;
} 

enum selint_error free_policy_node(struct policy_node *to_free) {
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	switch (to_free->flavor) {
		case NODE_AV_RULE:
			free_av_rule(to_free->data.av);
			break;
		case NODE_M4_CALL:
			free(to_free->data.m4_name);
			break;
		default:
			if (to_free->data.string != NULL) {
				free(to_free->data.string);
			}
			break;
	}

	// Free children
	struct policy_node *cur = to_free->first_child;
	while (cur) {
		struct policy_node *about_to_free = cur;
		cur = cur->next;

		free_policy_node(about_to_free);
		if (cur->prev) {
			cur->prev = NULL;
		}
	}

	to_free->first_child = NULL;

	return SELINT_SUCCESS;
}

void free_string_list(char **list) {
	if (list == NULL) {
		return;
	}
	char * cur_string = list[0];
	while (cur_string) {
		free(cur_string++);
	}
}

enum selint_error free_av_rule(struct av_rule *to_free) {

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free_string_list(to_free->perms);

	to_free->sources = to_free->targets = to_free->object_classes = to_free->perms = NULL;

	free(to_free);

	return SELINT_SUCCESS;}
