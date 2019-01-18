#include <stdlib.h>
#include <stdio.h>

#include "check_hooks.h"

#define ALLOC_NODE(nl)	if (ck->nl) {\
				loc = ck->nl;\
				while (loc->next) { loc = loc->next; }\
				loc->next = malloc(sizeof(struct check_node));\
				loc = loc->next;\
			} else {\
				ck->nl = malloc(sizeof(struct check_node));\
				loc = ck->nl;\
			}


enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck, struct check_result * (*check_function)(const struct check_data *check_data, const struct policy_node *node)) {

	struct check_node *loc;

	switch (check_flavor) {
		case NODE_FC_ENTRY:
			ALLOC_NODE(fc_entry_node_checks);
			break;

		case NODE_ERROR:
			ALLOC_NODE(error_node_checks);
			break;

		default:
			return SELINT_BAD_ARG;
	}

	loc->check_function = check_function;
	loc->next = NULL;

	return SELINT_SUCCESS;
}

enum selint_error call_checks(struct checks *ck, struct check_data *data, struct policy_node *node) {

	switch (node->flavor) {
		case NODE_FC_ENTRY:
			return call_checks_for_node_type(ck->fc_entry_node_checks, data, node);
		case NODE_ERROR:
			return call_checks_for_node_type(ck->error_node_checks, data, node);
		default:
			return SELINT_SUCCESS;
	}
}

enum selint_error call_checks_for_node_type(struct check_node *ck_list, struct check_data *data, struct policy_node *node) {

	struct check_node *cur = ck_list;

	while (cur) {
		struct check_result *res = cur->check_function(data, node);
		if (res) {
			res->lineno = node->lineno;
			display_check_result(res, data);
			free_check_result(res);
		}
		cur = cur->next;
	}
	return SELINT_SUCCESS;
}

void display_check_result(struct check_result *res, struct check_data *data) {

	printf("%s:%u: (%c): %s (%c-%03u)\n", data->filename, res->lineno, res->severity, res->message, res->severity, res->check_id);
}

void free_check_result(struct check_result *res) {
	free(res->message);
	free(res);
}

void free_checks(struct checks *to_free) {

	if (to_free->fc_entry_node_checks) {
		free_check_node(to_free->fc_entry_node_checks);
	}
	if (to_free->error_node_checks) {
		free_check_node(to_free->error_node_checks);
	}
	free(to_free);
}

void free_check_node(struct check_node *to_free) {

	if (to_free->next) {
		free_check_node(to_free->next);
	}
	free(to_free);

}

