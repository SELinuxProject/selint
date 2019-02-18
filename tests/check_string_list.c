#include <check.h>
#include <stdlib.h>

#include "../src/string_list.h"

START_TEST (test_str_in_sl) {

	struct string_list *sl = calloc(1, sizeof(struct string_list));

	sl->string = strdup("foo");
	sl->next = calloc(1, sizeof(struct string_list));
	sl->next->string = strdup("bar");

	ck_assert_int_eq(1, str_in_sl("foo", sl));
	ck_assert_int_eq(1, str_in_sl("bar", sl));
	ck_assert_int_eq(0, str_in_sl("baz", sl));

	ck_assert_int_eq(0, str_in_sl("foo", NULL));

	free_string_list(sl);

}
END_TEST

Suite *string_list_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("String_list");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_str_in_sl);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = string_list_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
