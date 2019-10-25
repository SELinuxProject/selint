#ifndef IF_CHECKS_H
#define IF_CHECKS_H

#include "check_hooks.h"

/*********************************************
* Check to make sure all interfaces and templates have a comment above them
* Called on NODE_IF_DEF and NODE_TEMP_DEF nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue C-004
*********************************************/
struct check_result *check_interface_definitions_have_comment(const struct
                                                              check_data *data,
                                                              const struct
                                                              policy_node
                                                              *node);

/*********************************************
* Check that all types referenced in interface are listed in its require block
* (or declared in that template)
* Called on NODE_AV_RULE, NODE_TT_RULE and NODE_IF_CALL nodes.
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-002
*********************************************/
struct check_result *check_type_used_but_not_required_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node);

/*********************************************
* Check that all types listed in require block are actually used in the interface
* Called on NODE_DECL nodes
* data - metadata about the file
* node - the node to check
* returns NULL if passed or check_result for issue W-003
*********************************************/
struct check_result *check_type_required_but_not_used_in_if(const struct
                                                            check_data *data,
                                                            const struct
                                                            policy_node *node);

#endif
