#include <check.h>
#include <stdlib.h>

#include "../src/string_list.h"
#include "../src/runner.h"

START_TEST (test_is_check_enabled) {
	struct string_list *con_e = calloc(1, sizeof(struct string_list));
	con_e->string = strdup("S-001");

	struct string_list *con_d = calloc(1, sizeof(struct string_list));
	con_d->string = strdup("S-001");
	con_d->next = calloc(1, sizeof(struct string_list));
	con_d->next->string = strdup("S-002");
	con_d->next->next = calloc(1, sizeof(struct string_list));
	con_d->next->next->string = strdup("S-003");

	struct string_list *cl_e = calloc(1, sizeof(struct string_list));
	cl_e->string = strdup("S-002");

	struct string_list *cl_d = calloc(1, sizeof(struct string_list));
	cl_d->string = strdup("S-004");

	ck_assert_int_eq(is_check_enabled("S-001", con_e, con_d, cl_e, cl_d, 0), 1);
	ck_assert_int_eq(is_check_enabled("S-002", con_e, con_d, cl_e, cl_d, 0), 1);
	ck_assert_int_eq(is_check_enabled("S-003", con_e, con_d, cl_e, cl_d, 0), 0);
	ck_assert_int_eq(is_check_enabled("S-004", con_e, con_d, cl_e, cl_d, 0), 0);

	ck_assert_int_eq(is_check_enabled("S-001", con_e, con_d, cl_e, cl_d, 1), 0);
	ck_assert_int_eq(is_check_enabled("S-002", con_e, con_d, cl_e, cl_d, 1), 1);
	ck_assert_int_eq(is_check_enabled("S-003", con_e, con_d, cl_e, cl_d, 1), 0);
	ck_assert_int_eq(is_check_enabled("S-004", con_e, con_d, cl_e, cl_d, 1), 0);

	free_string_list(con_e);
	free_string_list(con_d);
	free_string_list(cl_e);
	free_string_list(cl_d);

}
END_TEST

Suite *runner_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Runner");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_is_check_enabled);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = runner_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
