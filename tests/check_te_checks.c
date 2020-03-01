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

#include "test_utils.h"

#include "../src/te_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_te_order) {
	struct check_data *cd = calloc(1, sizeof(struct check_data));
	cd->flavor = FILE_TE_FILE;
	cd->config_check_data = calloc(1, sizeof(struct config_check_data));
	cd->config_check_data->order_conf = ORDER_REF;

	struct policy_node *head = calloc(1, sizeof(struct policy_node));

	head->flavor = NODE_TE_FILE;
	head->next = calloc(1, sizeof(struct policy_node));
	struct policy_node *cur = head->next;

	cur->flavor = NODE_DECL;
	cur->data.d_data = calloc(1, sizeof(struct declaration_data));
	cur->data.d_data->flavor = DECL_TYPE;
	cur->data.d_data->name = strdup("foo_t");

	cur->next = calloc(1, sizeof(struct policy_node));
	cur = cur->next;
	cur->flavor = NODE_IF_CALL;
	cur->data.ic_data = calloc(1, sizeof(struct if_call_data));
	cur->data.ic_data->name = strdup("domain_type");
	cur->data.ic_data->args = calloc(1, sizeof(struct string_list));
	cur->data.ic_data->args->string = strdup("foo_t");
	mark_transform_if("domain_type");

	cur->next = calloc(1, sizeof(struct policy_node));
	cur = cur->next;
	cur->flavor = NODE_AV_RULE;
	cur->data.av_data = make_example_av_rule();

	cur = head;

	while (cur) {
		ck_assert_ptr_null(check_te_order(cd, cur));
		cur = dfs_next(cur);
	}

	struct policy_node *cleanup = calloc(1, sizeof(struct policy_node));
	cleanup->flavor = NODE_CLEANUP;
	ck_assert_ptr_null(check_te_order(cd, cleanup));

	free(cd->config_check_data);
	free(cd);
	free_policy_node(head);
	free_policy_node(cleanup);
	free_all_maps();

}
END_TEST

START_TEST (test_check_require_block) {
	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_REQUIRE;
	struct check_data *cd = calloc(1, sizeof(struct check_data));

	cd->flavor = FILE_IF_FILE;
	ck_assert_ptr_null(check_require_block(cd, cur));

	cd->flavor = FILE_FC_FILE;
	ck_assert_ptr_null(check_require_block(cd, cur));

	cd->flavor = FILE_TE_FILE;
	cur->first_child = calloc(1, sizeof(struct policy_node));
	cur->first_child->flavor = NODE_DECL;
	cur->first_child->data.d_data = calloc(1, sizeof(struct declaration_data));
	cur->first_child->data.d_data->flavor = DECL_TYPE;
	struct check_result *res = check_require_block(cd, cur);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_REQUIRE);

	free_check_result(res);

	cur->flavor = NODE_GEN_REQ;

	res = check_require_block(cd, cur);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_REQUIRE);

	free_check_result(res);
	free(cd);
	free_policy_node(cur);
}
END_TEST

START_TEST (test_check_useless_semicolon) {
	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_SEMICOLON;

	struct check_data *cd = calloc(1, sizeof(struct check_data));

	struct check_result *res = check_useless_semicolon(cd, cur);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'S');
	ck_assert_int_eq(res->check_id, S_ID_SEMICOLON);

	free_check_result(res);
	free(cd);
	free_policy_node(cur);
}
END_TEST

START_TEST (test_check_no_explicit_declaration) {
	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	struct check_data *cd = calloc(1, sizeof(struct check_data));

	cur->flavor = NODE_AV_RULE;
	cur->data.av_data = make_example_av_rule();

	cd->flavor = FILE_IF_FILE;
	cd->mod_name = strdup("foo");

	ck_assert_ptr_null(check_no_explicit_declaration(cd, cur));

	cd->flavor = FILE_TE_FILE;

	// If the type isn't found, we don't do anything
	ck_assert_ptr_null(check_no_explicit_declaration(cd, cur));

	insert_into_decl_map("foo_t", "foo", DECL_TYPE);
	insert_into_decl_map("other_t", "other", DECL_TYPE);

	ck_assert_ptr_null(check_no_explicit_declaration(cd, cur));

	insert_into_decl_map("bar_t", "bar", DECL_TYPE);

	struct check_result *res = check_no_explicit_declaration(cd, cur);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(W_ID_NO_EXPLICIT_DECL, res->check_id);

	free_check_result(res);

	// Require block
	cur->prev = calloc(1, sizeof(struct policy_node));
	cur->prev->next = cur;
	cur = cur->prev;
	cur->flavor = NODE_REQUIRE;
	union node_data nd;
	nd.d_data = NULL;
	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_child(cur, NODE_START_BLOCK, nd, 0));
	nd.d_data = calloc(1, sizeof(struct declaration_data));
	nd.d_data->flavor = DECL_TYPE;
	nd.d_data->name = strdup("bar_t");
	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_child(cur, NODE_DECL, nd, 0));

	ck_assert_ptr_null(check_no_explicit_declaration(cd, cur->next));

	cur->flavor = NODE_GEN_REQ;

	ck_assert_ptr_null(check_no_explicit_declaration(cd, cur->next));

	free(cur->first_child->next->data.d_data->name);
	cur->first_child->next->data.d_data->name = strdup("baz_t");

	res = check_no_explicit_declaration(cd, cur->next);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(W_ID_NO_EXPLICIT_DECL, res->check_id);

	free_check_result(res);
	free_all_maps();
	free(cd->mod_name);
	free(cd);
	free_policy_node(cur);
}
END_TEST

START_TEST (test_check_module_if_call_in_optional) {
	struct check_result *res;

	char *foo_read_str = strdup("foo_read");
	char *bar_read_str = strdup("bar_read");

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_IF_CALL;
	struct if_call_data *ic_data = calloc(1, sizeof(struct if_call_data));
	cur->data.ic_data = ic_data;
	ic_data->name = foo_read_str;
	struct check_data *cd = calloc(1, sizeof(struct check_data));
	cd->mod_name = strdup("baz");

	insert_into_ifs_map("foo_read", "foo");
	insert_into_mods_map("foo", "module");

	res = check_module_if_call_in_optional(cd, cur);

	ck_assert_ptr_nonnull(res);
	free_check_result(res);

	ic_data->name = bar_read_str;
	insert_into_ifs_map("bar_read", "bar");
	insert_into_mods_map("bar", "base");

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	cur->parent = calloc(1, sizeof(struct policy_node));
	cur->parent->flavor = NODE_OPTIONAL_POLICY;
	cur->parent->first_child = cur;

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	ic_data->name = foo_read_str;

	res = check_module_if_call_in_optional(cd, cur);
	ck_assert_ptr_null(res);

	free(bar_read_str);
	free(cd->mod_name);
	free(cd);
	free_all_maps();
	free_policy_node(cur->parent);
}
END_TEST

START_TEST (test_check_attribute_interface_nameclash) {
	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_DECL;

	node->data.d_data = calloc(1, sizeof(struct declaration_data));
	node->data.d_data->flavor = DECL_ATTRIBUTE;
	node->data.d_data->name = strdup("foo");

	ck_assert_ptr_null(check_attribute_interface_nameclash(NULL, node));

	insert_into_ifs_map("foo", "bar");

	struct check_result *res = check_attribute_interface_nameclash(NULL, node);

	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq(res->severity, 'E');
	ck_assert_int_eq(res->check_id, E_ID_ATTR_IF_CLASH);
	free_check_result(res);

	free_policy_node(node);
	free_all_maps();
}
END_TEST

Suite *te_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("TE_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_te_order);
	tcase_add_test(tc_core, test_check_require_block);
	tcase_add_test(tc_core, test_check_useless_semicolon);
	tcase_add_test(tc_core, test_check_no_explicit_declaration);
	tcase_add_test(tc_core, test_check_module_if_call_in_optional);
	tcase_add_test(tc_core, test_check_attribute_interface_nameclash);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = te_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
