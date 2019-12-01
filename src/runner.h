#ifndef RUNNER_H
#define RUNNER_H

#include "check_hooks.h"
#include "selint_error.h"
#include "parse_functions.h"
#include "file_list.h"

/****************************************************
* Parse a policy file
* filename - The name of the files to parse.
* flavor - The node type corresponding to the type of file (TE or IF)
* Returns the head of the parsed AST or NULL on failure
****************************************************/
struct policy_node *parse_one_file(char *filename, enum node_flavor flavor);

/****************************************************
* Determine whether a specific check is enabled based on the
* config file and the command line arguments
****************************************************/
int is_check_enabled(const char *check_name,
                     struct string_list *config_enabled_checks,
                     struct string_list *config_disabled_checks,
                     struct string_list *cl_enabled_checks,
                     struct string_list *cl_disabled_checks, int only_enabled);

/****************************************************
* Allocate and populate a checks structure with the list of checks enabled for
* this run.  Caller is responsible for freeing
* level - The severity level to load checks at and above
* Returns the allocated checks structure or NULL on failure
****************************************************/
struct checks *register_checks(char level,
                               struct string_list *config_enabled_checks,
                               struct string_list *config_disabled_checks,
                               struct string_list *cl_enabled_checks,
                               struct string_list *cl_disabled_checks,
                               int only_enabled);

/****************************************************
* Parse all the provided te or if files, storing their parsed ASTs
* in the provided list
* files - The files to parse.  This list is updated with parsed ASTs
* flavor - The node type corresponding to the sorts of files in this list
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error parse_all_files_in_list(struct policy_file_list *files, enum node_flavor flavor);

/****************************************************
* Parse all the provided fc files, storing their parsed ASTs
* in the provided list
* files - The files to parse.  This list is updated with parsed ASTs
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error parse_all_fc_files_in_list(struct policy_file_list *files);

/****************************************************
* Run all checks for a certain file
* ck - The checks structure
* data - metadata about the file
* head - The head of the AST for that file
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_checks_on_one_file(struct checks *ck,
                                         struct check_data *data,
                                         struct policy_node *head);

/****************************************************
* Run all checks on all files of a certain type (te, if or fc)
* ck - The checks structure
* flavor - The type of file to check
* files - The list of files of that type to check
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor,
                                 struct policy_file_list *files);

/****************************************************
* Run the complete analysis, checking all files and reporting results
* ck - The checks structure
* te_files - The list of te files to check
* if_files - The list of if files to check
* fc_files - The list of fc files to check
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_analysis(struct checks *ck,
                               struct policy_file_list *te_files,
                               struct policy_file_list *if_files,
                               struct policy_file_list *fc_files);
#endif
