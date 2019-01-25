#include <check.h>

#include "../src/selint_config.h"

#define CONFIGS_DIR "sample_configs/"
#define SEVERITY_CONVENTION_FILENAME CONFIGS_DIR "severity_convention.conf"
#define SEVERITY_STYLE_FILENAME CONFIGS_DIR "severity_style.conf"
#define SEVERITY_WARNING_FILENAME CONFIGS_DIR "severity_warning.conf"
#define SEVERITY_ERROR_FILENAME CONFIGS_DIR "severity_error.conf"
#define SEVERITY_FATAL_FILENAME CONFIGS_DIR "severity_fatal.conf"

START_TEST (test_parse_config_severity) {
	char severity = '\0';

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_CONVENTION_FILENAME, &severity));
	ck_assert_int_eq('C', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_STYLE_FILENAME, &severity));
	ck_assert_int_eq('S', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_WARNING_FILENAME, &severity));
	ck_assert_int_eq('W', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_ERROR_FILENAME, &severity));
	ck_assert_int_eq('E', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_FATAL_FILENAME, &severity));
	ck_assert_int_eq('F', severity);
}
END_TEST

Suite *selint_config_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("SELint_config");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_config_severity);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = selint_config_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
