#ifndef RUNNER_H
#define RUNNER_H

#include "check_hooks.h"
#include "selint_error.h"
#include "parse_functions.h"
#include "file_list.h"

struct policy_node * parse_one_file(char *filename);

/****************************************************
 * Run all checks for a certain file
 * head - The head of the AST for that file
 * Returns SELINT_SUCCESS on success or an error code
 ****************************************************/
enum selint_error run_checks_on_one_file(struct checks *ck, struct check_data *data, struct policy_node *head);

enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor, struct policy_file_list *files);

#endif
