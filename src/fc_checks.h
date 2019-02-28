#ifndef FC_CHECKS_H
#define FC_CHECKS_H

#include "check_hooks.h"

/*********************************************
 * Check for issues with file context labels type field.
 * Called on NODE_FC_ENTRY nodes.
 * node - the node to check
 * returns NULL if passed or check_result for issue S-002
 *********************************************/
struct check_result *check_file_context_types_in_mod(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Check for potentially unescaped regex characters.
 * Called on NODE_FC_ENTRY nodes;
 * node - the node to check
 * returns NULL if called on a node type other than error node
 * or a check_result for issue W-004
 *********************************************/
struct check_result *check_file_context_regex(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Report an error on error nodes in a file_context file
 * node - the node to check
 * returns NULL if called on a node type other than error node
 * or a check_result for issue E-002
 *********************************************/
struct check_result *check_file_context_error_nodes(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Check for issues with file context labels user field
 * node - the node to check
 * returns NULL if passed or check_result for issue E-003
 *********************************************/
struct check_result *check_file_context_users(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Check for issues with file context labels role field.
 * Called on NODE_FC_ENTRY nodes.
 * node - the node to check
 * returns NULL if passed or check_result for issue E-004
 *********************************************/
struct check_result *check_file_context_roles(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Check for issues with file context labels type field.
 * Called on NODE_FC_ENTRY nodes.
 * node - the node to check
 * returns NULL if passed or check_result for issue E-005
 *********************************************/
struct check_result *check_file_context_types_exist(const struct check_data *data, const struct policy_node *node);

#endif
