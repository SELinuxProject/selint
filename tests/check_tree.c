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

#include "../src/tree.h"
#include "../src/maps.h"

START_TEST (test_insert_policy_node_child) {

	struct policy_node parent_node;
	parent_node.parent = NULL;
	parent_node.next = NULL;
	parent_node.prev = NULL;
	parent_node.first_child = NULL;
	parent_node.flavor = NODE_TE_FILE;
	parent_node.data.str = NULL;

	union node_data nd;
	nd.av_data =  make_example_av_rule();

	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_child(&parent_node, NODE_AV_RULE, nd, 1234));

	ck_assert_ptr_null(parent_node.next);
	ck_assert_ptr_nonnull(parent_node.first_child);
	ck_assert_ptr_eq(parent_node.first_child->data.av_data, nd.av_data);
	ck_assert_int_eq(parent_node.first_child->flavor, NODE_AV_RULE);
	ck_assert_int_eq(parent_node.first_child->lineno, 1234);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(parent_node.first_child));

}
END_TEST

START_TEST (test_insert_policy_node_next) {

	struct policy_node prev_node;
	prev_node.parent = NULL;
	prev_node.next = NULL;
	prev_node.prev = NULL;
	prev_node.first_child = NULL;
	prev_node.flavor = NODE_TE_FILE;
	prev_node.data.str = NULL;

	union node_data nd;
	nd.av_data = make_example_av_rule();

	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_next(&prev_node, NODE_AV_RULE, nd, 1234));

	ck_assert_ptr_null(prev_node.first_child);
	ck_assert_ptr_nonnull(prev_node.next);
	ck_assert_ptr_eq(prev_node.next->data.av_data, nd.av_data);
	ck_assert_int_eq(prev_node.next->flavor, NODE_AV_RULE);
	ck_assert_int_eq(prev_node.next->lineno, 1234);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(prev_node.next));

}
END_TEST

START_TEST (test_is_template_call) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));

	ck_assert_int_eq(0, is_template_call(node));

	struct if_call_data *data = calloc(1, sizeof(struct if_call_data));
	data->name = strdup("foo");
	node->data.ic_data = data;

	ck_assert_int_eq(0, is_template_call(node));

	node->flavor = NODE_IF_CALL;

	ck_assert_int_eq(0, is_template_call(node));

	insert_call_into_template_map("foo", data);

	ck_assert_int_eq(1, is_template_call(node));

	free_policy_node(node);
	free_all_maps();

}
END_TEST

START_TEST (test_get_types_in_node_av) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	node->data.av_data = make_example_av_rule();

	struct string_list *out = get_names_in_node(node);

	struct string_list *cur = out;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_1);

	cur = cur->next;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_2);

	cur = cur->next;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_3);

	ck_assert_ptr_null(cur->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_tt) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_TT_RULE;

	node->data.tt_data = calloc(1, sizeof(struct type_transition_data));

	struct type_transition_data *tt_data = (struct type_transition_data *)node->data.tt_data;

	tt_data->sources = calloc(1, sizeof(struct string_list));
	tt_data->sources->string = strdup(EXAMPLE_TYPE_3);

	tt_data->targets = calloc(1, sizeof(struct string_list));
	tt_data->targets->string = strdup(EXAMPLE_TYPE_2);

	tt_data->default_type = strdup(EXAMPLE_TYPE_1);

	struct string_list *out = get_names_in_node(node);

	struct string_list *cur = out;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_3);

	cur = cur->next;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_2);

	cur = cur->next;

	ck_assert_ptr_nonnull(cur);
	ck_assert_str_eq(cur->string, EXAMPLE_TYPE_1);

	ck_assert_ptr_null(cur->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_dd) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_DECL;

	node->data.d_data = calloc(1, sizeof(struct declaration_data));

	struct declaration_data *d_data = (struct declaration_data *)node->data.d_data;

	d_data->name = strdup(EXAMPLE_TYPE_2);

	struct string_list *out = get_names_in_node(node);

	ck_assert_ptr_nonnull(out);

	ck_assert_str_eq(out->string, EXAMPLE_TYPE_2);

	ck_assert_ptr_null(out->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_if_call) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_IF_CALL;

	node->data.ic_data = calloc(1, sizeof(struct if_call_data));

	struct if_call_data *if_data = (struct if_call_data *)node->data.ic_data;

	if_data->name = strdup("foo_read");
	if_data->args = calloc(1, sizeof(struct string_list));
	if_data->args->string = strdup("bar_t");
	if_data->args->next = calloc(1, sizeof(struct string_list));
	if_data->args->next->string = strdup("baz_t");

	struct string_list *out = get_names_in_node(node);

	ck_assert_ptr_nonnull(out);

	ck_assert_str_eq(out->string, "bar_t");
	ck_assert_str_eq(out->next->string, "baz_t");

	ck_assert_ptr_null(out->next->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_no_types) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_ERROR;

	ck_assert_ptr_null(get_names_in_node(node));

	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_exclusion) {
	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	node->data.av_data = calloc(1, sizeof(struct av_rule_data));
	node->data.av_data->sources = calloc(1, sizeof(struct string_list));
	node->data.av_data->sources->string = strdup("domain");
	node->data.av_data->sources->next = calloc(1, sizeof(struct string_list));
	node->data.av_data->sources->next->string = strdup("-init_t");

	struct string_list *out = get_names_in_node(node);
	ck_assert_ptr_nonnull(out);

	ck_assert_str_eq(out->string, "domain");
	ck_assert_str_eq(out->next->string, "init_t"); // Strip "-"
	ck_assert_ptr_null(out->next->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

Suite *tree_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Tree");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_insert_policy_node_child);
	tcase_add_test(tc_core, test_insert_policy_node_next);
	tcase_add_test(tc_core, test_is_template_call);
	tcase_add_test(tc_core, test_get_types_in_node_av);
	tcase_add_test(tc_core, test_get_types_in_node_tt);
	tcase_add_test(tc_core, test_get_types_in_node_dd);
	tcase_add_test(tc_core, test_get_types_in_node_if_call);
	tcase_add_test(tc_core, test_get_types_in_node_no_types);
	tcase_add_test(tc_core, test_get_types_in_node_exclusion);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = tree_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
