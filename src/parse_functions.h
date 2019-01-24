#ifndef PARSING_FUNCTIONS_H
#define PARSING_FUNCTIONS_H

#include <uthash.h>

#include "selint_error.h"
#include "tree.h"
#include "maps.h"

/**********************************
 * begin_parsing_te
 * Called at the beginning of parsing a te file to set up AST for a te file
 * cur (in, out) - Will be allocated to point to the first node of the tree
 * module_name (in) - The name of the policy module
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error begin_parsing_te(struct policy_node **cur, char *module_name, int yylineno);

/**********************************
 * Set the name of the current module to mn
 **********************************/
void set_current_module_name(char *mn);

/**********************************
 * Return the name of the current module
 **********************************/
char *get_current_module_name();

/**********************************
 * insert_declaration
 * Add a declaration node at the next node in the tree, allocating all memory for it
 * cur (in, out) - The current spot in the tree.  Will be updated to point to
 *	the newly allocated declaration node
 * flavor (in)- What sort of declaration this is
 * name (in) - The name of the item being declared
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error insert_declaration(struct policy_node **cur, enum decl_flavor flavor, char *name, int lineno); // TODO: Some declarations take things like attribute lists

/**********************************
 * insert_av_rule
 * Add an av rule node at the next node in the tree, allocating all memory for it
 * cur (in, out) - The current spot in the tree.  Will be updated to point to
 *	the newly allocated av rule node
 * flavor (in) - What sort of av rule this is
 * sources (in) - (memory allocated by caller) the sources in the rule
 * targets (in) - (memory allocated by caller) the targets in the rule
 * object_classes (in) - (memory allocated by caller) the object classes in the rule
 * perms (in) - (memory allocated by caller) the perms in the rule
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error insert_av_rule(struct policy_node **cur, enum av_rule_flavor flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms, int lineno);

enum selint_error insert_type_transition(struct policy_node **cur, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, char *default_type, char *name, int lineno);

enum selint_error insert_interface_call(struct policy_node **cur, char *name, struct string_list *args, int lineno);

/**********************************
 * begin_optional_policy
 * Add an optional policy node at the next node in the tree.  Create its first child
 * as the start of the block.  Set cur to the child node. Allocate all memory for
 * both nodes.
 * cur (in, out) - The current spot in the tree.  Will be updated to point to the
 * first child of the optional_policy node
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error begin_optional_policy(struct policy_node **cur, int lineno);

/**********************************
 * end_optional_policy
 * Complete the optional policy block by moving cur back up to the parent level
 * cur (in, out) - The current spot in the tree.  Will be updated to point to the
 * parent optional policy node
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error end_optional_policy(struct policy_node **cur);

enum selint_error begin_interface_def(struct policy_node **cur, enum node_flavor flavor, char *name, int lineno);

enum selint_error end_interface_def(struct policy_node **cur);

enum selint_error begin_gen_require(struct policy_node **cur, int lineno);

enum selint_error end_gen_require(struct policy_node **cur);

enum selint_error begin_require(struct policy_node **cur, int lineno);

enum selint_error end_require(struct policy_node **cur);

/**********************************
 * cleanup_parsing
 * Call after all parsing is done to free up memory
 **********************************/
void cleanup_parsing();

#endif
