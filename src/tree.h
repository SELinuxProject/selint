#ifndef TREE_H
#define TREE_H

#include "selint_error.h"

enum node_flavor {
	NODE_TE_FILE,
	NODE_IF_FILE,
	NODE_FC_FILE,
	NODE_AV_RULE,
	NODE_TT_RULE,
	NODE_DECL,
	NODE_M4_CALL,
	NODE_OPTIONAL_POLICY,
	NODE_M4_ARG,
	NODE_START_BLOCK,
	NODE_IF_DEF,
	NODE_TEMP_DEF,
	NODE_IF_CALL,
	NODE_GEN_REQ,
	NODE_FC_ENTRY,
	NODE_ERROR // When a parsing error occurs, save an error node in the tree
};

enum av_rule_flavor {
	AV_RULE_ALLOW,
	AV_RULE_AUDITALLOW,
	AV_RULE_DONTAUDIT,
	AV_RULE_NEVERALLOW
};

enum decl_flavor {
	DECL_TYPE,
	DECL_ATTRIBUTE,
	DECL_ROLE
};

struct string_list {
	char *string;
	struct string_list *next;
};

struct av_rule_data {
	enum av_rule_flavor flavor;
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	struct string_list *perms;
};

struct type_transition_data {
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	char *default_type;
	char *name;
};

struct if_call_data {
	char *name;
	struct string_list *args;
};

struct declaration_data {
	enum decl_flavor flavor;
	char *name;
	struct string_list *attrs;
};

struct decl_list {
	struct declaration_data *decl;
	struct decl_list *next;
};

struct policy_node {
	struct policy_node *parent;
	struct policy_node *next;
	struct policy_node *prev;
	struct policy_node *first_child;
	enum node_flavor flavor;
	void *data;
	int lineno;
};

enum selint_error insert_policy_node_child(struct policy_node *parent, enum node_flavor flavor, void *data, int lineno); 

enum selint_error insert_policy_node_next(struct policy_node *prev, enum node_flavor flavor, void *data, int lineno); 

enum selint_error free_policy_node(struct policy_node *to_free);

void free_string_list(struct string_list *list);

enum selint_error free_av_rule_data(struct av_rule_data *to_free);

enum selint_error free_type_transition_data(struct type_transition_data *to_free);

enum selint_error free_if_call_data(struct if_call_data *to_free);

enum selint_error free_declaration_data(struct declaration_data *to_free);

enum selint_error free_decl_list(struct decl_list *to_free);

#endif
