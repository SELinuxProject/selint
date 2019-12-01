#ifndef CHECK_HOOKS_H
#define CHECK_HOOKS_H

#include "tree.h"
#include "selint_error.h"

enum convention_ids {
	C_ID_TE_ORDER = 1,
	C_ID_IF_COMMENT = 4
};

enum style_ids {
	S_ID_REQUIRE = 1,
	S_ID_FC_TYPE = 2
};

enum warn_ids {
	W_ID_NO_EXPLICIT_DECL = 1,
	W_ID_NO_REQ           = 2,
	W_ID_UNUSED_REQ       = 3,
	W_ID_FC_REGEX         = 4,
	W_ID_IF_CALL_OPTIONAL = 5
};

enum error_ids {
	E_ID_FC_ERROR = 2,
	E_ID_FC_USER  = 3,
	E_ID_FC_ROLE  = 4,
	E_ID_FC_TYPE  = 5
};

enum fatal_ids {
	F_ID_POLICY_SYNTAX = 1,
	F_ID_INTERNAL      = 2
};

enum file_flavor {
	FILE_TE_FILE,
	FILE_IF_FILE,
	FILE_FC_FILE
};

struct check_data {
	char *mod_name;
	char *filename;
	enum file_flavor flavor;
};

// A check is responsible for filling out all fields except lineno
// which is filled out by the calling function.`
struct check_result {
	unsigned int lineno;
	char severity;
	unsigned int check_id;
	char *message;
};

struct check_node {
	struct check_result *(*check_function) (const struct check_data * data,
	                                        const struct policy_node * node);
	char *check_id;
	struct check_node *next;
};

struct checks {
	struct check_node *te_file_node_checks;
	struct check_node *av_rule_node_checks;
	struct check_node *tt_rule_node_checks;
	struct check_node *decl_node_checks;
	struct check_node *if_def_node_checks;
	struct check_node *temp_def_node_checks;
	struct check_node *if_call_node_checks;
	struct check_node *require_node_checks;
	struct check_node *gen_req_node_checks;
	struct check_node *fc_entry_node_checks;
	struct check_node *error_node_checks;
	struct check_node *cleanup_checks;
};

/*********************************************
* Add an check to be called on check_flavor nodes
* check_flavor - The flavor of node to call the check for
* ck - The check structure to add the check to
* check_id - The ID code for the check
* check_function - the check to add
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck,
                            const char *check_id,
                            struct check_result *(*check_function)(const struct
                                                                   check_data *
                                                                   check_data,
                                                                   const struct
                                                                   policy_node
                                                                   * node));

/*********************************************
* Call all registered checks for node->flavor node types
* and write any error messages to STDOUT
* ck - The checks structure
* data - Metadata about the file
* node - the node to check
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error call_checks(struct checks *ck,
                              struct check_data *data,
                              struct policy_node *node);

/*********************************************
* Helper function for call_checks that takes the appropriate
* list of checks for the node flavor and writes any error messages to STDOUT
* ck_list - The checks to run
* data - Metadata about the file
* node - the node to check
* returns SELINT_SUCCESS or an error code on failure
*********************************************/
enum selint_error call_checks_for_node_type(struct check_node *ck_list,
                                            struct check_data *data,
                                            struct policy_node *node);

/*********************************************
* Display a result message for a positive check finding
* res - Information about the result of the check
* data - Metadata about the file
*********************************************/
void display_check_result(struct check_result *res, struct check_data *data);

/*********************************************
* Creates a check_result, using a printf style format string and optional
* arguments to generate a message
* severity - The severity of the check result
* check_id - The check identifier
* format - A printf style format string
*********************************************/
struct check_result *make_check_result(char severity,
                                       unsigned int check_id,
                                       char *format, ...);

/*********************************************
* Generates a check result for an internal error (F-002)
* string - The error message to display
*********************************************/
struct check_result *alloc_internal_error(char *string);

void free_check_result(struct check_result *);

void free_checks(struct checks *to_free);

void free_check_node(struct check_node *to_free);

#endif
