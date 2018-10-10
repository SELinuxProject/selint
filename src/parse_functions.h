#ifndef PARSING_FUNCTIONS_H
#define PARSING_FUNCTIONS_H

#include "selint_error.h"
#include "tree.h"

enum selint_error begin_parsing_te(struct policy_node *cur, char *module_name);

enum selint_error insert_declaration(struct policy_node **cur, char *flavor, char *name); // TODO: Some declarations take things like attribute lists

enum selint_error insert_av_rule(struct policy_node **cur, char *flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms);

enum selint_error begin_optional_policy(struct policy_node **cur);

#endif
