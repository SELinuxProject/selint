/*
* Copyright 2019 Tresys Technology, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <check.h>

#include "../src/string_list.h"
#include "../src/selint_config.h"

#define CONFIGS_DIR "sample_configs/"
#define SEVERITY_CONVENTION_FILENAME CONFIGS_DIR "severity_convention.conf"
#define SEVERITY_STYLE_FILENAME CONFIGS_DIR "severity_style.conf"
#define SEVERITY_WARNING_FILENAME CONFIGS_DIR "severity_warning.conf"
#define SEVERITY_ERROR_FILENAME CONFIGS_DIR "severity_error.conf"
#define SEVERITY_FATAL_FILENAME CONFIGS_DIR "severity_fatal.conf"
#define CHECKS_FILENAME CONFIGS_DIR "check_config.conf"
#define BAD_FORMAT_1 CONFIGS_DIR "bad_format.conf"
#define BAD_FORMAT_2 CONFIGS_DIR "bad_format_2.conf"
#define BAD_OPTION CONFIGS_DIR "invalid_option.conf"
#define BAD_SEVERITY CONFIGS_DIR "severity_invalid.conf"

START_TEST (test_parse_config_severity) {
	char severity = '\0';

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_CONVENTION_FILENAME, 0, &severity, NULL, NULL));
	ck_assert_int_eq('C', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_STYLE_FILENAME, 0, &severity, NULL, NULL));
	ck_assert_int_eq('S', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_WARNING_FILENAME, 0, &severity, NULL, NULL));
	ck_assert_int_eq('W', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_ERROR_FILENAME, 0, &severity, NULL, NULL));
	ck_assert_int_eq('E', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_FATAL_FILENAME, 0, &severity, NULL, NULL));
	ck_assert_int_eq('F', severity);
}
END_TEST

START_TEST (test_parse_config_checks) {
	char severity = '\0';
	struct string_list *dis = NULL; 
	struct string_list *en = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(CHECKS_FILENAME, 0, &severity, &dis, &en));

	ck_assert_ptr_nonnull(dis);
	ck_assert_str_eq(dis->string, "E-003");
	ck_assert_str_eq(dis->next->string, "E-004");
	ck_assert_ptr_null(dis->next->next);

	ck_assert_ptr_null(en);

	free_string_list(dis);
	dis = NULL;
	free_string_list(en);
	en = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(CHECKS_FILENAME, 1, &severity, &dis, &en));

	ck_assert_ptr_nonnull(dis);
	ck_assert_str_eq(dis->string, "E-003");
	ck_assert_str_eq(dis->next->string, "E-004");
	ck_assert_ptr_null(dis->next->next);

	ck_assert_str_eq(en->string, "E-003");
	ck_assert_ptr_null(en->next);

	free_string_list(dis);
	free_string_list(en);

}
END_TEST

START_TEST (test_bad_configs) {
	char severity = '\0';
	struct string_list *dis = NULL;
	struct string_list *en = NULL;

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_FORMAT_1, 0, &severity, &dis, &en));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_FORMAT_2, 0, &severity, &dis, &en));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_OPTION, 0, &severity, &dis, &en));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_SEVERITY, 0, &severity, &dis, &en));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

}
END_TEST

Suite *selint_config_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("SELint_config");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_config_severity);
	tcase_add_test(tc_core, test_parse_config_checks);
	tcase_add_test(tc_core, test_bad_configs);
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
