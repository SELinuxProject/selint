#ifndef CHECK_HOOKS_H
#define CHECK_HOOKS_H

#include "tree.h"
#include "selint_error.h"

enum style_ids {
	S_ID_FC_TYPE = 2
};

enum error_ids {
	E_ID_FC_TYPE = 5
};

enum fatal_ids {
	F_ID_POLICY_SYNTAX = 1,
	F_ID_INTERNAL = 2
};

enum file_flavor {
	FILE_TE_FILE,
	FILE_IF_FILE,
	FILE_FC_FILE
};

struct check_data {
	char *mod_name;
	enum file_flavor flavor;
};

struct check_result {
	int lineno;
	char severity;
	int check_id;
	char *message;
};

struct check_node {
	struct check_result * (*check_function)(const struct check_data *data, struct policy_node *node);
	struct check_node *next;
};

struct checks {
	struct check_node *fc_entry_node_checks;
	struct check_node *error_node_checks;
};

/*********************************************
 * Add an check to be called on check_flavor nodes
 * check_flavor - The flavor of node to call the check for
 * ck - The check structure to add the check to
 * check_function - the check to add
 * returns SELINT_SUCCESS or an error code on failure
 *********************************************/
enum selint_error add_check(enum node_flavor check_flavor, struct checks *ck, struct check_result * (*check_function)(const struct check_data *check_data, struct policy_node *node));

/*********************************************
 * Call all registered checks for check_flavor node types
 * and write any error messages to STDOUT 
 * check_flavor - the node type to run checks for
 * node - the node to check
 * returns SELINT_SUCCESS or an error code on failure
 *********************************************/
enum selint_error call_checks(enum node_flavor check_flavor, struct policy_node *node);

void free_check_result(struct check_result *);

#endif
