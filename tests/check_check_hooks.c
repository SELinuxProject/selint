#include <check.h>
#include <stdlib.h>

#include "../src/check_hooks.h"

struct check_result * example_check(const struct check_data *check_data, struct policy_node *node);

struct check_result * example_check(__attribute__((unused)) const struct check_data *check_data, 
				  __attribute__((unused)) struct policy_node *node) {
	return (struct check_result *) NULL;
}

START_TEST (test_add_check) {
	struct checks *ck = malloc(sizeof(struct checks));
	memset(ck, 0, sizeof(struct checks));

	ck_assert_int_eq(SELINT_SUCCESS, add_check(NODE_FC_ENTRY, ck, example_check));

	ck_assert_ptr_null(ck->error_node_checks);
	ck_assert_ptr_nonnull(ck->fc_entry_node_checks);

	ck_assert_ptr_eq(ck->fc_entry_node_checks->check_function, example_check);

	free_checks(ck);

}
END_TEST

Suite *check_hooks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Check_hooks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_add_check);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = check_hooks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
