#ifndef TREE_H
#define TREE_H

#include "selint_error.h"
#include "string_list.h"

enum node_flavor {
	NODE_TE_FILE,
	NODE_IF_FILE,
	NODE_FC_FILE,
	NODE_AV_RULE,
	NODE_TT_RULE,
	NODE_TM_RULE,
	NODE_TC_RULE,
	NODE_ROLE_ALLOW,
	NODE_DECL,
	NODE_ALIAS,
	NODE_TYPE_ALIAS,
	NODE_M4_CALL,
	NODE_OPTIONAL_POLICY,
	NODE_OPTIONAL_ELSE,
	NODE_M4_ARG,
	NODE_START_BLOCK,
	NODE_IF_DEF,
	NODE_TEMP_DEF,
	NODE_IF_CALL,
	NODE_REQUIRE,
	NODE_GEN_REQ,
	NODE_PERMISSIVE,
	NODE_FC_ENTRY,
	NODE_COMMENT,
	NODE_EMPTY,
	NODE_ERROR              // When a parsing error occurs, save an error node in the tree
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
	DECL_ROLE,
	DECL_USER,
	DECL_CLASS,
	DECL_PERM
};

enum tt_flavor {
	TT_TT,
	TT_TM,
	TT_TC,
	TT_RT
};

struct av_rule_data {
	enum av_rule_flavor flavor;
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	struct string_list *perms;
};

struct role_allow_data {
	char *from;
	char *to;
};

struct type_transition_data {
	struct string_list *sources;
	struct string_list *targets;
	struct string_list *object_classes;
	char *default_type;
	char *name;
	enum tt_flavor flavor;
};

struct if_call_data {
	char *name;
	struct string_list *args;
};

struct if_call_list {
	struct if_call_data *call;
	struct if_call_list *next;
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

struct sel_context {
	int has_gen_context;    // 1 if context is wrapped in gen_context, 0 if not
	char *user;
	char *role;
	char *type;
	char *range;
};

struct fc_entry {
	char *path;
	char obj;
	struct sel_context *context;
};

union node_data {
	struct av_rule_data *av_data;
	struct role_allow_data *ra_data;
	struct type_transition_data *tt_data;
	struct if_call_data *ic_data;
	struct declaration_data *d_data;
	struct fc_entry *fc_data;
	char *str;
};

struct policy_node {
	struct policy_node *parent;
	struct policy_node *next;
	struct policy_node *prev;
	struct policy_node *first_child;
	enum node_flavor flavor;
	union node_data data;
	char *exceptions;
	unsigned int lineno;
};

enum selint_error insert_policy_node_child(struct policy_node *parent,
                                           enum node_flavor flavor, union node_data data,
                                           unsigned int lineno);

enum selint_error insert_policy_node_next(struct policy_node *prev,
                                          enum node_flavor flavor, union node_data data,
                                          unsigned int lineno);

// Returns 1 if the node is a template call, and 0 if not
int is_template_call(struct policy_node *node);

char *get_name_if_in_template(struct policy_node *cur);

struct string_list *get_types_in_node(const struct policy_node *node);

struct string_list *get_types_required(const struct policy_node *node);

enum selint_error free_policy_node(struct policy_node *to_free);

enum selint_error free_av_rule_data(struct av_rule_data *to_free);

enum selint_error free_ra_data(struct role_allow_data *to_free);

enum selint_error free_type_transition_data(struct type_transition_data
                                            *to_free);

enum selint_error free_if_call_data(struct if_call_data *to_free);

enum selint_error free_declaration_data(struct declaration_data *to_free);

enum selint_error free_decl_list(struct decl_list *to_free);

// Only free the list, not what it's pointing to
enum selint_error free_if_call_list(struct if_call_list *to_free);

void free_fc_entry(struct fc_entry *to_free);

void free_sel_context(struct sel_context *to_free);

#endif
