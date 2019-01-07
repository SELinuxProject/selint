#include <stdlib.h>

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


enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck, struct check_result * (*check_function)(const struct check_data *check_data, struct policy_node *node)) {

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

void free_check_result(struct check_result *res) {
	free(res->message);
	free(res);
}
