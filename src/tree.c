#include <stddef.h>
#include <stdlib.h>

#include "tree.h"
#include "selint_error.h"

enum selint_error insert_policy_node_child(struct policy_node *parent,
				enum node_flavor flavor,
				void *data) {

	if (parent == NULL) {
		return SELINT_BAD_ARG;
	}

	struct policy_node *to_insert = malloc(sizeof(struct policy_node));
	if (!to_insert) {
		return SELINT_OUT_OF_MEM;
	}

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

enum selint_error insert_policy_node_next(struct policy_node *prev,
				enum node_flavor flavor,
				void *data) {

	if (prev == NULL) {
		return SELINT_BAD_ARG;
	}

	struct policy_node *to_insert = malloc(sizeof(struct policy_node));
	if (!to_insert) {
		return SELINT_OUT_OF_MEM;
	}

	prev->next = to_insert;

	to_insert->parent = prev->parent;
	to_insert->next = NULL;
	to_insert->first_child = NULL;
	to_insert->flavor = flavor;
	to_insert->data = data;
	to_insert->prev = prev;

	return SELINT_SUCCESS;
}

enum selint_error free_policy_node(struct policy_node *to_free) {
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	switch (to_free->flavor) {
		case NODE_AV_RULE:
			free_av_rule_data(to_free->data);
			break;
		case NODE_TT_RULE:
			free_type_transition_data(to_free->data);
			break;
		case NODE_IF_CALL:
			free_if_call_data(to_free->data);
			break;
		case NODE_DECL:
			free_declaration_data(to_free->data);
			break;
		default:
			if (to_free->data != NULL) {
				free(to_free->data);
			}
			break;
	}

	free_policy_node(to_free->first_child);
	to_free->first_child = NULL;

	struct policy_node *cur = to_free->next;
	while (cur) {
		struct policy_node *about_to_free = cur;
		cur = cur->next;

		free_policy_node(about_to_free);
		if (cur && cur->prev) {
			cur->prev = NULL;
		}
	}

	to_free->first_child = NULL;

	free(to_free);

	return SELINT_SUCCESS;
}

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

enum selint_error free_av_rule_data(struct av_rule_data *to_free) {

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free_string_list(to_free->perms);

	to_free->sources = to_free->targets = to_free->object_classes = to_free->perms = NULL;

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_type_transition_data(struct type_transition_data *to_free) {

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->sources);
	free_string_list(to_free->targets);
	free_string_list(to_free->object_classes);
	free(to_free->default_type);
	free(to_free->name);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_if_call_data(struct if_call_data *to_free) {

	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free(to_free->name);
	free_string_list(to_free->args);

	free(to_free);

	return SELINT_SUCCESS;
}

enum selint_error free_declaration_data(struct declaration_data *to_free) {
	if (to_free == NULL) {
		return SELINT_BAD_ARG;
	}

	free_string_list(to_free->attrs);
	free(to_free->name);

	free(to_free);

	return SELINT_SUCCESS;
}
