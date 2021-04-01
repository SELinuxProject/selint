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
#include <stdlib.h>

#include "../src/fc_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_file_context_types_exist) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->type = strdup("foo_t");

	node->data.fc_data = entry;

	struct check_result *res = check_file_context_types_exist(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_TYPE);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	insert_into_decl_map("foo_t", "foo", DECL_TYPE);

	res = check_file_context_types_exist(data, node);

	ck_assert_ptr_null(res);

	free_all_maps();
	free(data->mod_name);
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_types_exist_bad_flavor) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_TE_FILE;

	struct check_result *res = check_file_context_types_exist(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq('F', res->severity);
	ck_assert_int_eq(F_ID_INTERNAL, res->check_id);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);
	free(data->mod_name);
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_types_in_mod) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->filename = strdup("foo");
	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;
	const struct config_check_data cfg = { ORDER_LAX, {}, true, true, NULL };
	data->config_check_data = &cfg;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->type = strdup("foo_t");

	node->data.fc_data = entry;

	struct check_result *res = check_file_context_types_in_mod(data, node);

	ck_assert_ptr_null(res);

	insert_into_decl_map("foo_t", "bar", DECL_TYPE);

	res = check_file_context_types_in_mod(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_FC_TYPE);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	free(data->mod_name);
	data->mod_name = strdup("bar");

	res = check_file_context_types_exist(data, node);

	ck_assert_ptr_null(res);

	free(res);

	free_all_maps();
	free(data->mod_name);
	free(data->filename);
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_roles) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->role = strdup("object_r");

	node->data.fc_data = entry;

	struct check_result *res = check_file_context_roles(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_ROLE);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	insert_into_decl_map("object_r", "files", DECL_ROLE);

	res = check_file_context_roles(data, node);

	ck_assert_ptr_null(res);

	free(res);

	free_all_maps();
	free(data->mod_name);
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_users) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));

	entry->context->user = strdup("system_u");

	node->data.fc_data = entry;

	struct check_result *res = check_file_context_users(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_USER);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	insert_into_decl_map("system_u", "files", DECL_USER);

	res = check_file_context_users(data, node);

	ck_assert_ptr_null(res);

	free(res);

	free_all_maps();
	free(data->mod_name);
	free(data);
	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_error_nodes) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));

	node->flavor = NODE_FC_ENTRY;

	struct check_result *res = check_file_context_error_nodes(data, node);

	ck_assert_ptr_null(res);

	node->flavor = NODE_ERROR;

	res = check_file_context_error_nodes(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_ERROR);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	free(data->mod_name);
	free(data);
	free_policy_node(node);
}
END_TEST

START_TEST (test_fc_checks_handle_null_context_fields) {

	struct check_data *data = malloc(sizeof(struct check_data));

	data->filename = strdup("foo");
	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));

	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));

	node->data.fc_data = entry;

	ck_assert_ptr_null(check_file_context_types_exist(data, node));
	ck_assert_ptr_null(check_file_context_types_in_mod(data, node));
	ck_assert_ptr_null(check_file_context_roles(data, node));
	ck_assert_ptr_null(check_file_context_users(data, node));

	free(data->filename);
	free(data->mod_name);
	free(data);

	free_policy_node(node);

}
END_TEST

START_TEST (test_check_file_context_regex) {
	struct check_data *data = malloc(sizeof(struct check_data));

	data->mod_name = strdup("foo");
	data->flavor = FILE_FC_FILE;

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;

	struct fc_entry *entry = malloc(sizeof(struct fc_entry));
	memset(entry, 0, sizeof(struct fc_entry));
	entry->context = malloc(sizeof(struct sel_context));
	memset(entry->context, 0, sizeof(struct sel_context));
	entry->path = strdup("path.with.unescpaed.dots");

	node->data.fc_data = entry;

	struct check_result *res = check_file_context_regex(data, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'W');
	ck_assert_int_eq(res->check_id, W_ID_FC_REGEX);
	ck_assert_ptr_nonnull(res->message);

	free_check_result(res);

	free(entry->path);
	entry->path = strdup("path\\.with\\.escaped\\.dots");

	res = check_file_context_regex(data, node);
	ck_assert_ptr_null(res);

	free(entry->path);
	entry->path = strdup("brackets\\.are[.s.kipped.]\\.");

	res = check_file_context_regex(data, node);
	ck_assert_ptr_null(res);

	free(entry->path);
	entry->path = strdup("unclosed[bracket");

	res = check_file_context_regex(data, node);
	ck_assert_ptr_null(res);

	free(entry->path);
	entry->path = strdup("escaped[brackets\\]in.brackets]");

	res = check_file_context_regex(data, node);
	ck_assert_ptr_null(res);

	free(data->mod_name);
	free(data);
	free_policy_node(node);
}
END_TEST

START_TEST (test_check_file_contexts_duplicate_entry){
	struct check_data *data = malloc(sizeof(struct check_data));

	data->filename = strdup("foo.fc");

	struct policy_node *node = malloc(sizeof(struct policy_node));
	memset(node, 0, sizeof(struct policy_node));
	node->flavor = NODE_FC_ENTRY;
	node->lineno = 1;

	struct fc_entry *node_entry = malloc(sizeof(struct fc_entry));
	memset(node_entry, 0, sizeof(struct fc_entry));
	node_entry->context = malloc(sizeof(struct sel_context));
	memset(node_entry->context, 0, sizeof(struct sel_context));

	node_entry->path = strdup("/foo/test/file");
	node_entry->obj = '-';
	node_entry->context->has_gen_context = 1;
	node_entry->context->range = strdup("s0");
	node_entry->context->role = strdup("object_r");
	node_entry->context->user = strdup("system_u");
	node_entry->context->type = strdup("foo_t");

	node->data.fc_data = node_entry;

	struct fc_entry *map_entry = malloc(sizeof(struct fc_entry));
	memset(map_entry, 0, sizeof(struct fc_entry));
	map_entry->context = malloc(sizeof(struct sel_context));
	memset(map_entry->context, 0, sizeof(struct sel_context));

	map_entry->path = strdup("/foo/test/file");
	map_entry->obj = '-';
	map_entry->context->has_gen_context = 1;
	map_entry->context->range = strdup("s0");
	map_entry->context->role = strdup("object_r");
	map_entry->context->user = strdup("system_u");
	map_entry->context->type = strdup("foo_t");

	struct fc_entry_map_info *info = malloc(
			sizeof(struct fc_entry_map_info));
	info->entry = map_entry;
	info->file_name = strdup(data->filename);
	info->lineno = 2;

	insert_into_fc_entries_map(info);

	/****************    test1    *********************
	 * check two duplicate within the same file none  *
	 * of which are within any ifdef/ifndef           *
	 **************************************************/
	struct check_result *res = check_file_contexts_duplicate_entry(data,node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);


	/****************    test2    *********************
	 * checking for one duplicate within ifdef and    *
	 * the other not within any ifdef/ifndef.         *
	 **************************************************/
	node_entry->conditional = malloc(sizeof(struct conditional_data));
	memset(node_entry->conditional, 0, sizeof(struct conditional_data));
	node_entry->conditional->condition = strdup("distro_gentoo");
	node_entry->conditional->flavor = CONDITION_IFDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test3    *********************
	 * checking for one duplicate within ifndef and   *
	 * the other not within any ifdef/ifndef.         *
	 **************************************************/
	node_entry->conditional->flavor = CONDITION_IFNDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test4    *********************
	 * checking for both duplicates within            *
	 * the same ifdef condition                       *
	 **************************************************/
	node_entry->conditional->flavor = CONDITION_IFDEF;

	map_entry->conditional = malloc(sizeof(struct conditional_data));
	memset(map_entry->conditional, 0, sizeof(struct conditional_data));
	map_entry->conditional->condition = strdup("distro_gentoo");
	node_entry->conditional->flavor = CONDITION_IFDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test5    *********************
	 * checking for both duplicates within            *
	 * the same ifndef condition                      *
	 **************************************************/
	node_entry->conditional->flavor = CONDITION_IFNDEF;
	map_entry->conditional->flavor = CONDITION_IFNDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test6    *********************
	 * checking for one duplicate within ifdef        *
	 * and the other one within ifndef of the same    *
	 * condition                                      *
	 **************************************************/
	node_entry->conditional->flavor = CONDITION_IFDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_null(res);

	/****************    test7    *********************
	 * checking for one duplicate within ifdef        *
	 * and the other one within ifndef and the        *
	 * conditions differ                              *
	 **************************************************/
	free(node_entry->conditional->condition);
	node_entry->conditional->condition = strdup("distro_redhat");

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test8    *********************
	 * checking for both duplicates within ifdef      *
	 * but the conditions differ                      *
	 **************************************************/
	map_entry->conditional->flavor = CONDITION_IFDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_null(res);

	/****************    test9    *********************
	 * checking for both duplicates within ifndef     *
	 * but the conditions differ                      *
	 **************************************************/
	node_entry->conditional->flavor = CONDITION_IFNDEF;
	map_entry->conditional->flavor = CONDITION_IFNDEF;

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	/****************    test10    *********************
	 * checking to find problematic duplicate          *
	 * across different file contexts.                 *
	 **************************************************/
	free(data->filename);
	data->filename = strdup("bar.fc");

	res = check_file_contexts_duplicate_entry(data, node);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_FC_DUPLICATE_ENTRY);
	ck_assert_ptr_nonnull(res->message);
	free_check_result(res);

	free_all_maps();
	free_fc_entry(map_entry);
	free(data->filename);
	free(data);
	free_policy_node(node);
}
END_TEST

static Suite *fc_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("FC_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_file_context_types_exist);
	tcase_add_test(tc_core, test_check_file_context_types_exist_bad_flavor);
	tcase_add_test(tc_core, test_check_file_context_types_in_mod);
	tcase_add_test(tc_core, test_check_file_context_roles);
	tcase_add_test(tc_core, test_check_file_context_users);
	tcase_add_test(tc_core, test_check_file_context_error_nodes);
	tcase_add_test(tc_core, test_check_file_context_regex);
	tcase_add_test(tc_core, test_fc_checks_handle_null_context_fields);
	tcase_add_test(tc_core, test_check_file_contexts_duplicate_entry);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = fc_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
