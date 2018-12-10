#include <check.h>
#include <stdlib.h>

#include "../src/template.h"

START_TEST (test_replace_m4) {
	char *orig1 = "$1_t";

	struct string_list *args = malloc(sizeof(struct string_list));
	args->string = strdup("foo");
	args->next = malloc(sizeof(struct string_list));
	args->next->string = strdup("bar");
	args->next->next = NULL;

	char *res = replace_m4(orig1, args);

	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("foo_t", res);

	free(res);

	char *orig2 = "$2";

	res = replace_m4(orig2, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("bar", res);

	free(res);

	char *orig3 = "test_$1_test";

	res = replace_m4(orig3, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("test_foo_test", res);

	free(res);

	char *orig4 = "test$2$1";

	res = replace_m4(orig4, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("testbarfoo", res);

	free(res);

	free_string_list(args);

}
END_TEST

START_TEST (test_replace_m4_too_few_args) {
	struct string_list *args = malloc(sizeof(struct string_list));
	args->string = strdup("foo");
	args->next = malloc(sizeof(struct string_list));
	args->next->string = strdup("bar");
	args->next->next = NULL;
	
	char *orig = "$3_t";

	ck_assert_ptr_null(replace_m4(orig, args));

	free_string_list(args);

}
END_TEST

Suite *template_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Template");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_replace_m4);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = template_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
