#include <check.h>
#include <stdlib.h>

#include "test_utils.h"

#include "../src/if_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_interface_defs_have_comment) {

	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	head->flavor = NODE_COMMENT;
	head->next = calloc(1, sizeof(struct policy_node));
	head->next->prev = head;

	head->next->flavor = NODE_IF_DEF;

	struct check_result *res = check_interface_definitions_have_comment(NULL, head->next);
	ck_assert_ptr_null(res);

	head->next->flavor = NODE_TEMP_DEF;
	
	res = check_interface_definitions_have_comment(NULL, head->next);
	ck_assert_ptr_null(res);

	head->flavor = NODE_IF_FILE;

	res = check_interface_definitions_have_comment(NULL, head->next);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq('C', res->severity);
	ck_assert_int_eq(C_ID_IF_COMMENT, res->check_id);

	free_check_result(res);

	head->next->flavor = NODE_AV_RULE;

	res = check_interface_definitions_have_comment(NULL, head->next);
	ck_assert_ptr_nonnull(res);
	ck_assert_int_eq('F', res->severity);
	ck_assert_int_eq(F_ID_INTERNAL, res->check_id);

	free_check_result(res);

	free_policy_node(head);
}
END_TEST

START_TEST(test_check_type_used_but_not_required_in_if) {

	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	head->flavor = NODE_IF_DEF;

	struct policy_node *cur = head->first_child = calloc(1, sizeof(struct policy_node));

	cur->flavor = NODE_GEN_REQ;
	cur->parent = head;

	cur->first_child = calloc(1, sizeof(struct policy_node));
	cur->first_child->parent = cur;
	cur = cur->first_child;

	cur->flavor = NODE_START_BLOCK;

	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->prev = cur;
	cur->next->parent = cur->parent;
	cur = cur->next;

	cur->flavor = NODE_DECL;

	struct declaration_data *data = calloc(1, sizeof(struct policy_node));

	cur->data = data;

	data->flavor = DECL_TYPE;
	data->name = strdup("bar_t");

	cur = cur->parent;

	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->prev = cur;
	cur->next->parent = cur->parent;

	cur = cur->next;

	cur->flavor = NODE_AV_RULE;
	cur->data = make_example_av_rule();

	insert_into_decl_map("foo_t", "test", DECL_TYPE);
	insert_into_decl_map("bar_t", "test", DECL_TYPE);
	insert_into_decl_map("baz_t", "test", DECL_TYPE);

	struct av_rule_data *av_data = cur->data;
	free(av_data->sources->string);
	av_data->sources->string = strdup("$1");

	struct check_result *res = check_type_used_but_not_required_in_if(NULL, cur);

	ck_assert_ptr_nonnull(res);

	ck_assert_int_eq(W_ID_NO_REQ, res->check_id);
	ck_assert_str_eq("Type baz_t is used in interface but not required", res->message);

	free_check_result(res);
	free_policy_node(head);
	free_all_maps();

}
END_TEST

START_TEST (test_check_type_required_but_not_used_in_if) {
	struct policy_node *head = calloc(1, sizeof(struct policy_node));
	head->flavor = NODE_IF_DEF;

	struct policy_node *cur = head->first_child = calloc(1, sizeof(struct policy_node));

	cur->flavor = NODE_GEN_REQ;
	cur->parent = head;

	cur->first_child = calloc(1, sizeof(struct policy_node));
	cur->first_child->parent = cur;
	cur = cur->first_child;

	cur->flavor = NODE_START_BLOCK;

	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->prev = cur;
	cur->next->parent = cur->parent;
	cur = cur->next;

	cur->flavor = NODE_DECL;

	struct declaration_data *data = calloc(1, sizeof(struct policy_node));

	cur->data = data;

	data->flavor = DECL_TYPE;
	data->name = strdup("bar_t");

	cur = cur->parent;

	cur->next = calloc(1, sizeof(struct policy_node));
	cur->next->prev = cur;
	cur->next->parent = cur->parent;

	cur = cur->next;

	cur->flavor = NODE_AV_RULE;
	cur->data = make_example_av_rule();

	cur = cur->prev->first_child->next; // the declaration

	ck_assert_ptr_null(check_type_required_but_not_used_in_if(NULL, cur));

	free(data->name);
	data->name = strdup("not_used_t");

	struct check_result *res = check_type_required_but_not_used_in_if(NULL, cur);
	ck_assert_ptr_nonnull(res);

	free_check_result(res);
	free_policy_node(head);

}
END_TEST

Suite *if_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("IF_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_interface_defs_have_comment);
	tcase_add_test(tc_core, test_check_type_used_but_not_required_in_if);
	tcase_add_test(tc_core, test_check_type_required_but_not_used_in_if);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = if_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
