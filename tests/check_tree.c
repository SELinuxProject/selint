#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "test_utils.h"

#include "../src/tree.h"

START_TEST (test_insert_policy_node_child) {

	struct policy_node parent_node;
	parent_node.parent = NULL;
	parent_node.next = NULL;
	parent_node.prev = NULL;
	parent_node.first_child = NULL;
	parent_node.flavor = NODE_TE_FILE;
	parent_node.data = NULL;

	struct av_rule_data *av_data = make_example_av_rule();

	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_child(&parent_node, NODE_AV_RULE, av_data, 1234));

	ck_assert_ptr_null(parent_node.next);
	ck_assert_ptr_nonnull(parent_node.first_child);
	ck_assert_ptr_eq(parent_node.first_child->data, av_data);
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
	prev_node.data = NULL;

	struct av_rule_data *av_data = make_example_av_rule();

	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node_next(&prev_node, NODE_AV_RULE, av_data, 1234));

	ck_assert_ptr_null(prev_node.first_child);
	ck_assert_ptr_nonnull(prev_node.next);
	ck_assert_ptr_eq(prev_node.next->data, av_data);
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
	node->data = data;

	ck_assert_int_eq(0, is_template_call(node));

	node->flavor = NODE_IF_CALL;

	ck_assert_int_eq(0, is_template_call(node));

	insert_call_into_template_map("foo", data);

	ck_assert_int_eq(1, is_template_call(node));
}
END_TEST

START_TEST (test_get_types_in_node_av) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_AV_RULE;

	node->data = make_example_av_rule();

	struct string_list *out = get_types_in_node(node);

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

	node->data = calloc(1, sizeof(struct type_transition_data));

	struct type_transition_data *tt_data = (struct type_transition_data *)node->data;

	tt_data->sources = calloc(1, sizeof(struct string_list));
	tt_data->sources->string = strdup(EXAMPLE_TYPE_3);

	tt_data->targets = calloc(1, sizeof(struct string_list));
	tt_data->targets->string = strdup(EXAMPLE_TYPE_2);

	tt_data->default_type = strdup(EXAMPLE_TYPE_1);

	struct string_list *out = get_types_in_node(node);

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

	node->data = calloc(1, sizeof(struct declaration_data));

	struct declaration_data *d_data = (struct declaration_data *)node->data;

	d_data->name = strdup(EXAMPLE_TYPE_2);

	struct string_list *out = get_types_in_node(node);

	ck_assert_ptr_nonnull(out);

	ck_assert_str_eq(out->string, EXAMPLE_TYPE_2);

	ck_assert_ptr_null(out->next);

	free_string_list(out);
	free_policy_node(node);
}
END_TEST

START_TEST (test_get_types_in_node_no_types) {

	struct policy_node *node = calloc(1, sizeof(struct policy_node));
	node->flavor = NODE_ERROR;

	ck_assert_ptr_null(get_types_in_node(node));

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
	tcase_add_test(tc_core, test_get_types_in_node_no_types);
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
