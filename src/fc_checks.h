/*
* Copyright 2019 Tresys Technology, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef FC_CHECKS_H
#define FC_CHECKS_H

#include "check_hooks.h"

/*********************************************
 * Check for wide dir path file contexts.
 * Called on NODE_FC_ENTRY nodes.
 * node - the node to check
 * returns NULL if passed or check_result for issue C-008
 *********************************************/
struct check_result *check_wide_dir_path_fcontext(const struct check_data
                                                  *data,
                                                  const struct policy_node
                                                  *node);

/*********************************************
* Check for issues with file context labels type field.
* Called on NODE_FC_ENTRY nodes.
* node - the node to check
* returns NULL if passed or check_result for issue S-002
*********************************************/
struct check_result *check_file_context_types_in_mod(const struct check_data
                                                     *data,
                                                     const struct policy_node
                                                     *node);

/*********************************************
* Check for gen_context calls that omit an mls component
* Called on NODE_FC_ENTRY nodes.
* node - the node to check
* returns NULL if passed or check_result for issue S-007
*********************************************/
struct check_result *check_gen_context_no_range(const struct check_data
                                                *data,
                                                const struct policy_node
                                                *node);


/*********************************************
* Check for potentially unescaped regex characters.
* Called on NODE_FC_ENTRY nodes;
* node - the node to check
* returns NULL if called on a node type other than error node
* or a check_result for issue W-004
*********************************************/
struct check_result *check_file_context_regex(const struct check_data *data,
                                              const struct policy_node *node);

/*********************************************
* Report an error on error nodes in a file_context file
* node - the node to check
* returns NULL if called on a node type other than error node
* or a check_result for issue E-002
*********************************************/
struct check_result *check_file_context_error_nodes(const struct check_data
                                                    *data,
                                                    const struct policy_node
                                                    *node);

/*********************************************
* Check for issues with file context labels user field
* node - the node to check
* returns NULL if passed or check_result for issue E-003
*********************************************/
struct check_result *check_file_context_users(const struct check_data *data,
                                              const struct policy_node *node);

/*********************************************
* Check for issues with file context labels role field.
* Called on NODE_FC_ENTRY nodes.
* node - the node to check
* returns NULL if passed or check_result for issue E-004
*********************************************/
struct check_result *check_file_context_roles(const struct check_data *data,
                                              const struct policy_node *node);

/*********************************************
* Check for issues with file context labels type field.
* Called on NODE_FC_ENTRY nodes.
* node - the node to check
* returns NULL if passed or check_result for issue E-005
*********************************************/
struct check_result *check_file_context_types_exist(const struct check_data
                                                    *data,
                                                    const struct policy_node
                                                    *node);

#endif
