#include <check.h>
#include <stdlib.h>

#include "../src/if_checks.h"
#include "../src/check_hooks.h"

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
	ck_assert_int_eq(C_IF_COMMENT, res->check_id);

	free(res);
	free_policy_node(head);
}
END_TEST

Suite *if_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("IF_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_interface_defs_have_comment);
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
