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

#include <string.h>
#include <stdlib.h>

#include "file_list.h"

void file_list_push_back(struct policy_file_list *list,
                         struct policy_file *file)
{

	if (list->tail) {
		list->tail->next = malloc(sizeof(struct policy_file_node));
		list->tail = list->tail->next;
	} else {
		list->head = list->tail =
			malloc(sizeof(struct policy_file_node));
	}
	list->tail->file = file;
	list->tail->next = NULL;
}

struct policy_file *make_policy_file(char *filename, struct policy_node *ast)
{
	struct policy_file *ret = malloc(sizeof(struct policy_file));

	ret->filename = strdup(filename);
	ret->ast = ast;
	return ret;
}

void free_file_list(struct policy_file_list *to_free)
{
	struct policy_file_node *cur = to_free->head;

	while (cur) {
		free(cur->file->filename);
		free_policy_node(cur->file->ast);
		free(cur->file);
		struct policy_file_node *tmp = cur;
		cur = cur->next;
		free(tmp);
	}
	free(to_free);
}
