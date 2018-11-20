#include <stdlib.h>
#include <string.h>

#include "parse_functions.h"
#include "selint_error.h"
#include "tree.h"

enum selint_error begin_parsing_te(struct policy_node **cur, char *module_name) {
	
	*cur = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}

	memset(*cur, 0, sizeof(struct policy_node));

	(*cur)->flavor = NODE_TE_FILE;

	(*cur)->data.string = strdup("example");

	return SELINT_SUCCESS;
}

enum selint_error insert_declaration(struct policy_node **cur, char *flavor, char *name) {
	//TODO: Handle attributes
	//TODO: Insert type in hash table (Actually, it should be on the first pass
	// after building the tree, right?)

	struct policy_node *old = *cur;

	(*cur)->next = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}


	*cur = (*cur)->next;
	memset(*cur, 0, sizeof(struct policy_node));

	(*cur)->parent = old->parent;
	(*cur)->prev = old;
	(*cur)->flavor = NODE_DECL;

	(*cur)->data.decl = (struct declaration *) malloc(sizeof(struct declaration));
	if (!(*cur)->data.decl) {
		return SELINT_OUT_OF_MEM;
	}

	memset((*cur)->data.decl, 0, sizeof(struct declaration));

	enum decl_flavor flavor_to_set = DECL_TYPE; // TODO: Other flavors

	(*cur)->data.decl->flavor = flavor_to_set;

	(*cur)->data.decl->name = strdup(name);

	//TODO: (*cur)->data.decl->

	return SELINT_SUCCESS;
}

enum selint_error insert_av_rule(struct policy_node **cur, char *flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms) {
	return SELINT_SUCCESS;
}


enum selint_error begin_optional_policy(struct policy_node **cur) {
	struct policy_node *old = *cur;

	(*cur)->next = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}

	*cur = (*cur)->next;
	memset(*cur, 0, sizeof(struct policy_node));

	(*cur)->parent = old->parent;
	(*cur)->prev = old;
	(*cur)->flavor = NODE_OPTIONAL_POLICY;

	(*cur)->first_child = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}
	memset((*cur)->first_child, 0, sizeof(struct policy_node));
	(*cur)->first_child->parent = *cur;

	*cur = (*cur)->first_child;
	(*cur)->flavor = NODE_START_BLOCK;

	return SELINT_SUCCESS;
}
