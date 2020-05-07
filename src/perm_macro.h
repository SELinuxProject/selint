/*
* Copyright 2020 The SELint Contributors
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

#ifndef PERMMACRO_H
#define PERMMACRO_H

#include "string_list.h"

/*********************************************
* permmacro_check
* Performs a check on the given class and permissions whether a declared
* permission-macro can be used to simplify the used permissions.
*   e.g. file:{ open read } leads to read_file_perms being suggested
* class (in) - The related class
* permissions (in) - The currently used permissions
* Returns - a string containing a message (which needs to be freed) or NULL.
*********************************************/
char *permmacro_check(const char *class, const struct string_list *permissions);

/*********************************************
* Free internal allocations
*********************************************/
void free_permmacros(void);

#endif
