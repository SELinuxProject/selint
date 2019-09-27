#ifndef TE_CHECKS_H
#define TE_CHECKS_H

#include "check_hooks.h"

/*********************************************
 * Check for the presence of require blocks in TE files.
 * Interface calls are to be prefered.
 * Called on NODE_REQUIRE and NODE_GEN_REQ nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue S-001
 *********************************************/
struct check_result *check_require_block(const struct check_data *data, const struct policy_node *node);

/*********************************************
 * Check for situations where interface or template calls into modules are not
 * in optional policy blocks
 * Called on NODE_IF_CALL nodes.
 * data - metadata about the file currently being scanned
 * node - the node to check
 * returns NULL if passed or check_result for issue E-001
 *********************************************/
struct check_result *check_module_if_call_in_optional(const struct check_data *data, const struct policy_node *node);

#endif
