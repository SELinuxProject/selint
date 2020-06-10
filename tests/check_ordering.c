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

#include "../src/runner.h"
#include "../src/ordering.h"
#include "../src/maps.h"

enum order_difference_reason always_greater(__attribute__((unused)) const struct ordering_metadata *order_data,
                                            __attribute__((unused)) const struct policy_node *first,
                                            __attribute__((unused)) const struct policy_node *second) {
	return 1;
}

enum order_difference_reason always_less(__attribute__((unused)) const struct ordering_metadata *order_data,
                                         __attribute__((unused)) const struct policy_node *first,
                                         __attribute__((unused)) const struct policy_node *second) {
	return -1;
}

START_TEST (test_prepare_ordering_metadata) {
	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	head->next = calloc(1, sizeof(struct policy_node));
	head->flavor = NODE_TE_FILE;
	struct policy_node *cur = head->next;
	cur->flavor = NODE_DECL;
	cur->next = calloc(1, sizeof(struct policy_node));
	cur = cur->next;
	cur->flavor = NODE_DECL;
	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->flavor = NODE_DECL;

	struct check_data data;
	data.mod_name = strdup("foo");

	struct ordering_metadata *o = prepare_ordering_metadata(&data, head);

	ck_assert_ptr_nonnull(o);
	ck_assert_ptr_nonnull(o->sections);
	ck_assert_ptr_nonnull(o->sections->section_name);
	ck_assert_uint_eq(o->order_node_len, 3);
	ck_assert_ptr_null(o->nodes[0].node);
	ck_assert_ptr_null(o->nodes[1].node);
	ck_assert_ptr_null(o->nodes[2].node);

	free(data.mod_name);
	free_ordering_metadata(o);
	free_policy_node(head);
}
END_TEST

#define POLICIES_DIR SAMPLE_POL_DIR
#define UNCOMMON_TE_FILENAME POLICIES_DIR "uncommon.te"

START_TEST (test_ordering_uncommon_policy) {
	struct policy_node *head = parse_one_file(UNCOMMON_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(head);

	struct check_data data;
	data.mod_name = strdup("foo");

	struct ordering_metadata *o = prepare_ordering_metadata(&data, head);

	ck_assert_ptr_nonnull(o);

	calculate_longest_increasing_subsequence(head, o, always_greater);

	ck_assert_ptr_eq(o->nodes[0].node, head->next);
	ck_assert_int_eq(o->nodes[0].in_order, 1);

	free(data.mod_name);
	free_ordering_metadata(o);
	free_policy_node(head);
	cleanup_parsing();
}
END_TEST

START_TEST (test_calculate_longest_increasing_subsequence) {
	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	head->flavor = NODE_TE_FILE;
	head->next = calloc(1, sizeof(struct policy_node));
	struct policy_node *cur = head->next;
	cur->flavor = NODE_DECL;
	cur->next = calloc(1, sizeof(struct policy_node));
	cur = cur->next;
	cur->flavor = NODE_DECL;
	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->flavor = NODE_DECL;

	struct check_data data;
	data.mod_name = strdup("foo");

	struct ordering_metadata *o = prepare_ordering_metadata(&data, head);

	ck_assert_ptr_nonnull(o);

	calculate_longest_increasing_subsequence(head, o, always_greater);

	ck_assert_ptr_eq(o->nodes[0].node, head->next);
	ck_assert_int_eq(o->nodes[0].in_order, 1);

	free_ordering_metadata(o);
	o = prepare_ordering_metadata(&data, head);

	calculate_longest_increasing_subsequence(head, o, always_less);
	ck_assert_ptr_eq(o->nodes[0].node, head->next);
	ck_assert_int_eq(o->nodes[0].in_order, 0);

	free(data.mod_name);
	free_ordering_metadata(o);
	free_policy_node(head);

}
END_TEST

START_TEST (test_add_section_info) {

	struct section_data *sections = calloc(1, sizeof(struct section_data));

	add_section_info(sections, "foo", 2);

	ck_assert_str_eq(sections->section_name, "foo");
	ck_assert_int_eq(sections->lines_sum, 2);
	ck_assert_int_eq(sections->lineno_count, 1);
	ck_assert_ptr_null(sections->next);

	add_section_info(sections, "foo", 4);

	ck_assert_str_eq(sections->section_name, "foo");
	ck_assert_int_eq(sections->lines_sum, 6);
	ck_assert_int_eq(sections->lineno_count, 2);
	ck_assert_ptr_null(sections->next);

	add_section_info(sections, "bar", 5);

	ck_assert_str_eq(sections->section_name, "foo");
	ck_assert_int_eq(sections->lines_sum, 6);
	ck_assert_int_eq(sections->lineno_count, 2);
	ck_assert_ptr_nonnull(sections->next);

	ck_assert_str_eq(sections->next->section_name, "bar");
	ck_assert_int_eq(sections->next->lines_sum, 5);
	ck_assert_int_eq(sections->next->lineno_count, 1);
	ck_assert_ptr_null(sections->next->next);

	free_section_data(sections);
}
END_TEST

START_TEST (test_get_section) {
	ck_assert_ptr_null(get_section(NULL));

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_TE_FILE;
	ck_assert_ptr_null(get_section(node));
	node->flavor = NODE_IF_FILE;
	ck_assert_ptr_null(get_section(node));
	node->flavor = NODE_FC_FILE;
	ck_assert_ptr_null(get_section(node));
	node->flavor = NODE_AV_RULE;
	node->data.av_data = calloc(1, sizeof(struct av_rule_data));
	node->data.av_data->sources = calloc(1, sizeof(struct string_list));
	node->data.av_data->sources->string = strdup("foo_t");
	ck_assert_str_eq("foo_t", get_section(node));
	free_av_rule_data(node->data.av_data);
	node->data.av_data = NULL;
	node->flavor = NODE_ROLE_ALLOW;
	ck_assert_str_eq("_non_ordered", get_section(node));
	node->flavor = NODE_DECL;
	ck_assert_str_eq("_declaration", get_section(node));
	node->flavor = NODE_ALIAS;
	ck_assert_str_eq("_declaration", get_section(node));
	node->flavor = NODE_TYPE_ALIAS;
	ck_assert_str_eq("_declaration", get_section(node));
	node->flavor = NODE_TYPE_ATTRIBUTE;
	ck_assert_str_eq("_declaration", get_section(node));

	node->flavor = NODE_OPTIONAL_POLICY;
	node->first_child = calloc(1, sizeof(struct policy_node));
	node->first_child->flavor = NODE_START_BLOCK;
	node->first_child->next = calloc(1, sizeof(struct policy_node));
	node->first_child->next->flavor = NODE_IF_CALL;
	node->first_child->next->data.ic_data = calloc(1, sizeof(struct if_call_data));
	node->first_child->next->data.ic_data->name = strdup("foo_read");
	node->first_child->next->data.ic_data->args = calloc(1, sizeof(struct string_list));
	node->first_child->next->data.ic_data->args->string = strdup("bar_t");

	ck_assert_str_eq("bar_t", get_section(node));

	node->flavor = NODE_REQUIRE;
	ck_assert_str_eq("_non_ordered", get_section(node));

	free_policy_node(node);
}
END_TEST

START_TEST (test_calculate_average_lines) {
	// Make sure no segfault on NULL.  No return to check.
	calculate_average_lines(NULL);

	struct section_data *sections = calloc(1, sizeof(struct section_data));

	sections->section_name = strdup("foo");
	sections->lineno_count = 4;
	sections->lines_sum = 21;
	sections->next = calloc(1, sizeof(struct section_data));
	sections->next->lineno_count = 10;
	sections->next->lines_sum = 40;

	calculate_average_lines(sections);

	ck_assert_float_eq_tol((float) 5.25, sections->avg_line, (float) 0.001);
	ck_assert_float_eq_tol((float) 4, sections->next->avg_line, (float) 0.001);

	free_section_data(sections);

}
END_TEST

START_TEST (test_get_local_subsection) {
	ck_assert_int_eq(LSS_UNKNOWN, get_local_subsection("foo", NULL, ORDER_REF));
	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;
	node->data.av_data = calloc(1, sizeof(struct av_rule_data));
	node->data.av_data->targets = calloc(1, sizeof(struct string_list));
	node->data.av_data->targets->string = strdup("self");

	ck_assert_int_eq(LSS_SELF, get_local_subsection("foo", node, ORDER_REF));

	free(node->data.av_data->targets->string);
	node->data.av_data->sources = calloc(1, sizeof(struct string_list));
	node->data.av_data->sources->string = strdup("foo_t");
	node->data.av_data->targets->string = strdup("foo_log_t");

	insert_into_decl_map("foo_t", "foo", DECL_TYPE);
	insert_into_decl_map("foo_log_t", "foo", DECL_TYPE);
	insert_into_decl_map("foo_config", "foo", DECL_ATTRIBUTE);

	ck_assert_int_eq(LSS_OWN, get_local_subsection("foo", node, ORDER_REF));

	free(node->data.av_data->targets->string);
	node->data.av_data->targets->string = strdup("foo_config");

	ck_assert_int_eq(LSS_OWN, get_local_subsection("foo", node, ORDER_REF));

	free(node->data.av_data->targets->string);
	node->data.av_data->targets->string = strdup("bar_data_t");
	insert_into_decl_map("bar_data_t", "bar", DECL_TYPE);

	// raw allow to other module.  Not mentioned in style guide
	ck_assert_int_eq(LSS_UNKNOWN, get_local_subsection("foo", node, ORDER_REF));

	free_all_maps();
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_local_subsection_related_if) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_IF_CALL;
	node->data.ic_data = malloc(sizeof(struct if_call_data));
	node->data.ic_data->name = strdup("foo_if");
	node->data.ic_data->args = sl_from_str("foo_t");

	insert_into_ifs_map("foo_if", "foo");
	insert_into_ifs_map("foo_sub_if", "foo_sub");

	ck_assert_int_eq(LSS_OWN, get_local_subsection("foo", node, ORDER_LIGHT));
	ck_assert_int_eq(LSS_RELATED, get_local_subsection("foo_sub", node, ORDER_LIGHT));
	ck_assert_int_eq(LSS_OTHER, get_local_subsection("foo_sub", node, ORDER_REF));

	free(node->data.ic_data->name);
	node->data.ic_data->name = strdup("foo_sub_if");

	ck_assert_int_eq(LSS_OWN, get_local_subsection("foo_sub", node, ORDER_LIGHT));
	ck_assert_int_eq(LSS_RELATED, get_local_subsection("foo", node, ORDER_LIGHT));
	ck_assert_int_eq(LSS_OTHER, get_local_subsection("foo", node, ORDER_REF));

	free_policy_node(node);
	free_all_maps();

}
END_TEST

START_TEST (test_compare_nodes_refpolicy) {
	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	struct policy_node *first = calloc(1, sizeof(struct policy_node));
	struct policy_node *second = calloc(1, sizeof(struct policy_node));
	head->next = first;
	first->next = second;

	first->flavor = NODE_DECL;
	second->flavor = NODE_AV_RULE;

	second->data.av_data = calloc(1, sizeof(struct av_rule_data));
	second->data.av_data->sources = calloc(1, sizeof(struct string_list));
	second->data.av_data->sources->string = strdup("foo_t");

	struct check_data data;
	data.mod_name = strdup("foo");

	struct ordering_metadata *o = prepare_ordering_metadata(&data, head);

	ck_assert_int_eq(ORDER_SECTION, compare_nodes_refpolicy(o, first, second));
	ck_assert_int_eq(-ORDER_SECTION, compare_nodes_refpolicy(o, second, first));

	free_av_rule_data(second->data.av_data);
	second->data.av_data = NULL;
	second->flavor = NODE_DECL;
	first->data.d_data = calloc(1, sizeof(struct declaration_data));
	second->data.d_data = calloc(1, sizeof(struct declaration_data));
	first->data.d_data->flavor = DECL_BOOL;
	second->data.d_data->flavor = DECL_ATTRIBUTE;

	ck_assert_int_eq(ORDER_DECLARATION_SUBSECTION, compare_nodes_refpolicy(o, first, second));

	first->data.d_data->flavor = DECL_TYPE;
	ck_assert_int_eq(-ORDER_DECLARATION_SUBSECTION, compare_nodes_refpolicy(o, first, second));

	free(data.mod_name);
	free_ordering_metadata(o);
	free_policy_node(head);
}
END_TEST

START_TEST (test_alphabetical_if_calls) {
	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	struct policy_node *first = calloc(1, sizeof(struct policy_node));
	struct policy_node *second = calloc(1, sizeof(struct policy_node));
	struct policy_node *third = calloc(1, sizeof(struct policy_node));

	head->next = first;
	first->next = second;
	second->next = third;

	first->flavor = NODE_IF_CALL;
	second->flavor = NODE_IF_CALL;
	third->flavor = NODE_IF_CALL;

	first->data.ic_data = malloc(sizeof(struct if_call_data));
	first->data.ic_data->name = strdup("moduleA_if1");
	first->data.ic_data->args = sl_from_str("foo_t");

	second->data.ic_data = malloc(sizeof(struct if_call_data));
	second->data.ic_data->name = strdup("moduleA_if2");
	second->data.ic_data->args = sl_from_str("foo_t");

	third->data.ic_data = malloc(sizeof(struct if_call_data));
	third->data.ic_data->name = strdup("moduleB_if");
	third->data.ic_data->args = sl_from_str("foo_t");

	struct check_data data;
	data.mod_name = strdup("foo");

	insert_into_ifs_map("moduleA_if1", "moduleA");
	insert_into_ifs_map("moduleA_if2", "moduleA");
	insert_into_ifs_map("moduleB_if", "moduleB");

	struct ordering_metadata *o = prepare_ordering_metadata(&data, head);

	ck_assert_int_eq(ORDER_EQUAL, compare_nodes_refpolicy(o, first, second));
	ck_assert_int_eq(ORDER_EQUAL, compare_nodes_refpolicy(o, second, first));

	ck_assert_int_eq(ORDER_ALPHABETICAL, compare_nodes_refpolicy(o, second, third));
	ck_assert_int_eq(-ORDER_ALPHABETICAL, compare_nodes_refpolicy(o, third, second));

	free(data.mod_name);
	free_ordering_metadata(o);
	free_policy_node(head);
}
END_TEST

Suite *ordering_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Ordering");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_prepare_ordering_metadata);
	tcase_add_test(tc_core, test_ordering_uncommon_policy);
	tcase_add_test(tc_core, test_calculate_longest_increasing_subsequence);
	tcase_add_test(tc_core, test_add_section_info);
	tcase_add_test(tc_core, test_get_section);
	tcase_add_test(tc_core, test_calculate_average_lines);
	tcase_add_test(tc_core, test_get_local_subsection);
	tcase_add_test(tc_core, test_get_local_subsection_related_if);
	tcase_add_test(tc_core, test_compare_nodes_refpolicy);
	tcase_add_test(tc_core, test_alphabetical_if_calls);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = ordering_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
