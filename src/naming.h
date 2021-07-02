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

#ifndef NAMING_H
#define NAMING_H

#include "tree.h"

/**********************************
* Check the given name with the given kind of declaration for naming
* convention violations.
* name (in) - the name of the declaration
* flavor (in) - the kind of declaration
* Returns NULL if check passes, else a violation reason.
**********************************/
const char *naming_decl_check(const char *name, enum decl_flavor flavor);

/**********************************
* Check the given interface name for naming
* convention violations.
* name (in) - the name of the interface
* module_name (in) - the name of the containing module
* Returns NULL if check passes, else a violation reason.
**********************************/
const char *naming_if_check(const char *name, const char *module_name);

/**********************************
* Check the given template name for naming
* convention violations.
* name (in) - the name of the template
* module_name (in) - the name of the containing module
* Returns NULL if check passes, else a violation reason.
**********************************/
const char *naming_temp_check(const char *name, const char *module_name);

#endif
