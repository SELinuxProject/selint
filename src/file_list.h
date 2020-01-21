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

#ifndef FILE_LIST_H
#define FILE_LIST_H

#include "tree.h"

struct policy_file {
	char *filename;
	struct policy_node *ast;
};

struct policy_file_node {
	struct policy_file *file;
	struct policy_file_node *next;
};

struct policy_file_list {
	struct policy_file_node *head;
	struct policy_file_node *tail;
};

void file_list_push_back(struct policy_file_list *list,
                         struct policy_file *file);

struct policy_file *make_policy_file(const char *filename, struct policy_node *ast);

void free_file_list(struct policy_file_list *to_free);

#endif
