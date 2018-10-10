#ifndef TREE_H
#define TREE_H

#include "selint_error.h"

enum node_flavor {
	NODE_AV_RULE,
	NODE_M4_CALL,
	NODE_OPTIONAL_POLICY,
	NODE_M4_ARG,
	NODE_TE_FILE,
	NODE_START_BLOCK
};

enum av_rule_flavor {
	AV_RULE_ALLOW,
	AV_RULE_AUDITALLOW,
	AV_RULE_DONTAUDIT,
	AV_RULE_NEVERALLOW
};

struct string_list {
	char *string;
	struct string_list *next;
};

struct av_rule {
	enum av_rule_flavor flavor;
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	struct string_list *perms;
};

union node_data {
	struct av_rule *av;
	char *m4_name;
	char *string;
};

struct policy_node {
	struct policy_node *parent;
	struct policy_node *next;
	struct policy_node *prev;
	struct policy_node *first_child;
	enum node_flavor flavor;
	union node_data data;
};

enum selint_error insert_policy_node(struct policy_node *parent, enum node_flavor flavor, union node_data data); 

enum selint_error free_policy_node(struct policy_node *to_free);

enum selint_error free_av_rule(struct av_rule *to_free);

#endif
