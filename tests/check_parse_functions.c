#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "../src/parse_functions.h"

#define EXAMPLE_TYPE_1 "foo_t"
#define EXAMPLE_TYPE_2 "bar_t"
#define EXAMPLE_TYPE_3 "baz_t"

START_TEST (test_begin_parsing_te) {

	struct policy_node *cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_parsing_te(&cur, "example"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_str_eq(cur->data.string, "example");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur));

}
END_TEST

Suite *parse_functions_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parse_Functions");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_begin_parsing_te);
	suite_add_tcase(s, tc_core);

	return s;
}
int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = parse_functions_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
