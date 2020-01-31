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

#ifndef TE_CHECKS_H
#define TE_CHECKS_H

#include "check_hooks.h"

/*********************************************
* Check for violations of te file ordering conventions.
* The refpolicy conventions (which is all that can be checked as of now are
* described at: https://github.com/SELinuxProject/refpolicy/wiki/StyleGuide
* Called on all nodes except fc file nodes, error nodes, NODE_IF_FILE and
* NODE_FC_FILE
* On NODE_TE_FILE nodes, it generates the ordering information for that file
* On other nodes, it checks the previously generated ordering information to
* determine whether to return an error.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue C-001
*********************************************/
struct check_result *check_te_order(const struct check_data *data,
                                    const struct policy_node *node);

/*********************************************
* Check for the presence of require blocks in TE files.
* Interface calls are to be prefered.
* Called on NODE_REQUIRE and NODE_GEN_REQ nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-001
*********************************************/
struct check_result *check_require_block(const struct check_data *data,
                                         const struct policy_node *node);

/*********************************************
* Check for useless semicolons after interface calls
* Called on IF_CALL nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue S-003
*********************************************/
struct check_result *check_useless_semicolon(const struct check_data *data,
                                             const struct policy_node *node);

/*********************************************
* Check for references to types in te files without an explicit declaration.
* We don't check types in .if or .fc files because those are similar issues
* handled by W-002 and E-005 respectively.
* This situation typically results in a compilation error, but in the event
* that an earlier interface call required the type it would not.
* Called on allow rule and interface call nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue W-001
*********************************************/
struct check_result *check_no_explicit_declaration(const struct check_data *data,
                                                   const struct policy_node *node);

/*********************************************
* Check for situations where interface or template calls into modules are not
* in optional policy blocks
* Called on NODE_IF_CALL nodes.
* data - metadata about the file currently being scanned
* node - the node to check
* returns NULL if passed or check_result for issue W-005
*********************************************/
struct check_result *check_module_if_call_in_optional(const struct check_data
                                                      *data,
                                                      const struct policy_node
                                                      *node);

#endif
