#ifndef PARSING_FUNCTIONS_H
#define PARSING_FUNCTIONS_H

#include "selint_error.h"
#include "tree.h"

/**********************************
 * begin_parsing_te
 * Called at the beginning of parsing a te file to set up AST for a te file
 * cur (in, out) - Will be allocated to point to the first node of the tree
 * module_name (in) - The name of the policy module
 *
 * Returns - SELINT error code
 * ********************************/
enum selint_error begin_parsing_te(struct policy_node **cur, char *module_name);

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
enum selint_error insert_declaration(struct policy_node **cur, char *flavor, char *name); // TODO: Some declarations take things like attribute lists


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
enum selint_error insert_av_rule(struct policy_node **cur, char *flavor, struct string_list *sources, struct string_list *targets, struct string_list *object_classes, struct string_list *perms);

/**********************************
 * begin_optional_policy
 * Add an optional policy node at the next node in the tree.  Create its first child
 * with the name of that node.  Set cur to the child node. Allocate all memory for
 * both nodes.
 * cur (in, out) - The current spot in the tree.  Will be updated to point to the
 * first child of the optional_policy node
 *
 * Returns - SELINT error code
 **********************************/
enum selint_error begin_optional_policy(struct policy_node **cur);

#endif
