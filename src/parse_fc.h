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

#ifndef PARSE_FC_H
#define PARSE_FC_H

#include <stdbool.h>

#include "tree.h"

// Takes in a null terminated string that is an fc entry and populates an fc_entry struct
struct fc_entry *parse_fc_line(char *line, struct conditional_data *conditional);

struct sel_context *parse_context(char *context_str);

// Return true if the line contains a defined custom fc macro, and false otherwise
bool check_for_fc_macro(const char *line, const struct string_list *custom_fc_macros);

// Parse an fc file and return a pointer to an abstract syntax tree representing the file
struct policy_node *parse_fc_file(const char *filename, const struct string_list *custom_fc_macros);
#endif
