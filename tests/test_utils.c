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

#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"

struct av_rule_data * make_example_av_rule(void) {

	// allow foo_t { bar_t baz_t }:file { read write getattr };
	struct av_rule_data *av_rule_data = malloc(sizeof(struct av_rule_data));

	av_rule_data->flavor = AV_RULE_ALLOW;

	av_rule_data->sources = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->sources);

	av_rule_data->sources->string = strdup(EXAMPLE_TYPE_1);
	ck_assert_ptr_nonnull(av_rule_data->sources->string);

	av_rule_data->sources->next = NULL;

	av_rule_data->targets = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->targets);

	av_rule_data->targets->string = strdup(EXAMPLE_TYPE_2);
	ck_assert_ptr_nonnull(av_rule_data->targets->string);

	av_rule_data->targets->next = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->targets->next);

	av_rule_data->targets->next->string = strdup(EXAMPLE_TYPE_3);
	ck_assert_ptr_nonnull(av_rule_data->targets->next->string);

	av_rule_data->targets->next->next = NULL;

	av_rule_data->object_classes = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->object_classes);

	av_rule_data->object_classes->string = strdup("file");
	ck_assert_ptr_nonnull(av_rule_data->object_classes->string);

	av_rule_data->object_classes->next = NULL;

	av_rule_data->perms = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->perms);

	av_rule_data->perms->string = strdup("read");
	ck_assert_ptr_nonnull(av_rule_data->perms->string);

	av_rule_data->perms->next = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->perms->next);

	av_rule_data->perms->next->string = strdup("write");
	ck_assert_ptr_nonnull(av_rule_data->perms->next->string);

	av_rule_data->perms->next->next = calloc(1,sizeof(struct string_list));
	ck_assert_ptr_nonnull(av_rule_data->perms->next->next);

	av_rule_data->perms->next->next->string = strdup("getattr");
	ck_assert_ptr_nonnull(av_rule_data->perms->next->next->string);

	av_rule_data->perms->next->next->next = NULL;

	return av_rule_data;

}
