#include <check.h>
#include <stdlib.h>

#include "../src/te_checks.h"
#include "../src/check_hooks.h"
#include "../src/maps.h"

START_TEST (test_check_module_if_call_in_optional) {

}
END_TEST

Suite *te_checks_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("TE_Checks");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_check_module_if_call_in_optional);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = te_checks_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
