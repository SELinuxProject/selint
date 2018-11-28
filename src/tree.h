#ifndef TREE_H
#define TREE_H

#include "selint_error.h"

enum node_flavor {
	NODE_AV_RULE,
	NODE_DECL,
	NODE_M4_CALL,
	NODE_OPTIONAL_POLICY,
	NODE_M4_ARG,
	NODE_TE_FILE,
	NODE_START_BLOCK,
	NODE_IF_DEF,
	NODE_GEN_REQ
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

struct declaration_data {
	enum decl_flavor flavor;
	char *name;
	struct string_list *attrs;
};

struct policy_node {
	struct policy_node *parent;
	struct policy_node *next;
	struct policy_node *prev;
	struct policy_node *first_child;
	enum node_flavor flavor;
	void *data;
};

enum selint_error insert_policy_node_child(struct policy_node *parent, enum node_flavor flavor, void *data); 

enum selint_error insert_policy_node_next(struct policy_node *prev, enum node_flavor flavor, void *data); 

enum selint_error free_policy_node(struct policy_node *to_free);

enum selint_error free_av_rule_data(struct av_rule_data *to_free);

enum selint_error free_declaration_data(struct declaration_data *to_free);

#endif
