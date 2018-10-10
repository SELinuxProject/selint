#include <stdlib.h>
#include <string.h>

#include "parse_functions.h"
#include "selint_error.h"
#include "tree.h"

enum selint_error begin_parsing_te(struct policy_node *cur, char *module_name) {
	
	cur = malloc(sizeof(struct policy_node));
	if (!cur) {
		return SELINT_OUT_OF_MEM;
	}

	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	cur->data.string = strdup("example");

	return SELINT_SUCCESS;
}

enum selint_error insert_declaration(struct policy_node **cur, char *flavor, char *name) {
	//TODO: Handle attributes
	//TODO: Insert type in hash table

	(*cur)->next = malloc(sizeof(struct policy_node));
	*cur = (*cur)->next;
	memset(*cur, 0, sizeof(struct policy_node));

	// TODO

	return SELINT_SUCCESS;
}

enum selint_error insert_av_rule(struct policy_node **cur, char *flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms) {
	return SELINT_SUCCESS;
}


enum selint_error begin_optional_policy(struct policy_node **cur) {
	return SELINT_SUCCESS;
}
