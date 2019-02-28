#include "fc_checks.h"
#include "maps.h"
#include "tree.h"

#define SETUP_FOR_FC_CHECK(node) \
	if (node->flavor != NODE_FC_ENTRY) {\
		return alloc_internal_error("File context type check called on non file context entry");\
	}\
	struct fc_entry *entry = (struct fc_entry *)node->data;\
	if (!entry) {\
		return alloc_internal_error("Policy node data field is NULL");\
	}\
	if (!entry->context) {\
		return NULL;\
	}\

struct check_result *check_file_context_types_in_mod(const struct check_data *check_data, const struct policy_node *node) {

	SETUP_FOR_FC_CHECK(node)

	char *type_decl_mod_name = look_up_in_decl_map(entry->context->type, DECL_TYPE);

	if (!type_decl_mod_name) {
		// If the type is not in any module, that's a different error
		// Returning success on an error condition may seem weird, but it is a
		// redundant condition with another check that will catch this if enabled.
		// Enabling this check and disabling the undeclared check is a valid (although
		// strange) configuration which will result in this condition not being logged,
		// but that is what the user has specifically requested in that situation.  The
		// more common case is having both checks on, and there we don't want to double
		// log
		return NULL;
	}

	if (strcmp(check_data->mod_name, type_decl_mod_name)) {
		return make_check_result('S', S_ID_FC_TYPE, "Type %s is declared in module %s, but used in file context here.", entry->context->type, type_decl_mod_name);
	}

	return NULL;
}

struct check_result *check_file_context_error_nodes(const struct check_data *data, const struct policy_node *node) {

	if (node->flavor != NODE_ERROR) {
		return NULL;
	}

	return make_check_result('E', E_ID_FC_ERROR, "Bad file context format");
}

struct check_result *check_file_context_users(const struct check_data *data, const struct policy_node *node) {

	SETUP_FOR_FC_CHECK(node)

	char *user_decl_filename = look_up_in_decl_map(entry->context->user, DECL_USER);

	if (!user_decl_filename) {
		return make_check_result('E', E_ID_FC_USER, "Nonexistent user (%s) listed in fc_entry", entry->context->user);
	}

	return NULL;
}

struct check_result *check_file_context_roles(const struct check_data *data, const struct policy_node *node) {

	SETUP_FOR_FC_CHECK(node)

	char *role_decl_filename = look_up_in_decl_map(entry->context->role, DECL_ROLE);

	if (!role_decl_filename) {
		return make_check_result('E', E_ID_FC_ROLE, "Nonexistent role (%s) listed in fc_entry", entry->context->role);
	}

	return NULL;
}

struct check_result * check_file_context_types_exist(const struct check_data *check_data, const struct policy_node *node) {

	SETUP_FOR_FC_CHECK(node)

	char *type_decl_filename = look_up_in_decl_map(entry->context->type, DECL_TYPE);

	if (!type_decl_filename) {
		return make_check_result('E', E_ID_FC_TYPE, "Nonexistent type (%s) listed in fc_entry", entry->context->type);
	}

	return NULL;
}
