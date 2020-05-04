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
struct policy_node *parse_one_file(const char *filename, enum node_flavor flavor);

/****************************************************
* Determine whether a specific check is enabled based on the
* config file and the command line arguments
****************************************************/
int is_check_enabled(const char *check_name,
                     const struct string_list *config_enabled_checks,
                     const struct string_list *config_disabled_checks,
                     const struct string_list *cl_enabled_checks,
                     const struct string_list *cl_disabled_checks,
                     int only_enabled);

/****************************************************
* Allocate and populate a checks structure with the list of checks enabled for
* this run.  Caller is responsible for freeing
* level - The severity level to load checks at and above
* Returns the allocated checks structure or NULL on failure
****************************************************/
struct checks *register_checks(char level,
                               const struct string_list *config_enabled_checks,
                               const struct string_list *config_disabled_checks,
                               const struct string_list *cl_enabled_checks,
                               const struct string_list *cl_disabled_checks,
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
enum selint_error parse_all_fc_files_in_list(struct policy_file_list *files,
                                             const struct string_list *custom_fc_macros);

/****************************************************
* Run all checks for a certain file
* ck - The checks structure
* data - metadata about the file
* head - The head of the AST for that file
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_checks_on_one_file(struct checks *ck,
                                         const struct check_data *data,
                                         const struct policy_node *head);

/****************************************************
* Run all checks on all files of a certain type (te, if or fc)
* ck - The checks structure
* flavor - The type of file to check
* files - The list of files of that type to check
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_all_checks(struct checks *ck, enum file_flavor flavor,
                                 struct policy_file_list *files,
                                 const struct config_check_data *ccd);

/****************************************************
* Run the complete analysis, checking all files and reporting results
* ck - The checks structure
* te_files - The list of te files to check
* if_files - The list of if files to check
* fc_files - The list of fc files to check
* context_te_files - Additional te files to parse, but not scan.  This is used
* to load symbols (eg type names) that may be referenced in scanned files.
* context_if_files - Additional if files to parse, but not scan.  This is used
* to load interface/template names and contents to do analysis on how they are
* used in scanned files.
* custom_fc_macros - Custom macros used in fc files defined in config
* ccd - Information loaded from the config to be given to checks
* Returns SELINT_SUCCESS on success or an error code
****************************************************/
enum selint_error run_analysis(struct checks *ck,
                               struct policy_file_list *te_files,
                               struct policy_file_list *if_files,
                               struct policy_file_list *fc_files,
                               struct policy_file_list *context_te_files,
                               struct policy_file_list *context_if_files,
                               const struct string_list *custom_fc_macros,
                               const struct config_check_data *ccd);

/****************************************************
* Display a summary of the analysis that was just run
* ck - The checks structure
* no return
****************************************************/
void display_run_summary(const struct checks *ck);

#endif
