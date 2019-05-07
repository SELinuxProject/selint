#ifndef TE_CHECKS_H
#define TE_CHECKS_H

#include "check_hooks.h"

/*********************************************
 * Check for situations where interface or template calls into modules are not
 * in optional policy blocks
 * Called on NODE_IF_CALL nodes.
 * node - the node to check
 * returns NULL if passed or check_result for issue E-001
 *********************************************/
struct check_result *check_module_if_call_in_optional(const struct check_data *data, const struct policy_node *node);

#endif
