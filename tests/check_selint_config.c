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
#include "../src/ordering.h"

#define CONFIGS_DIR SAMPLE_CONF_DIR
#define SEVERITY_CONVENTION_FILENAME CONFIGS_DIR "severity_convention.conf"
#define SEVERITY_STYLE_FILENAME CONFIGS_DIR "severity_style.conf"
#define SEVERITY_WARNING_FILENAME CONFIGS_DIR "severity_warning.conf"
#define SEVERITY_ERROR_FILENAME CONFIGS_DIR "severity_error.conf"
#define SEVERITY_FATAL_FILENAME CONFIGS_DIR "severity_fatal.conf"
#define CHECKS_FILENAME CONFIGS_DIR "check_config.conf"
#define REFPOL_ORDERING_FILENAME CONFIGS_DIR "refpolicy_ordering.conf"
#define ORDER_REQUIRES_FILENAME CONFIGS_DIR "order_requires.conf"
#define BAD_FORMAT_1 CONFIGS_DIR "bad_format.conf"
#define BAD_FORMAT_2 CONFIGS_DIR "bad_format_2.conf"
#define BAD_OPTION CONFIGS_DIR "invalid_option.conf"
#define BAD_SEVERITY CONFIGS_DIR "severity_invalid.conf"
#define BAD_ORDER CONFIGS_DIR "bad_order.conf"

START_TEST (test_parse_config_severity) {
	char severity = '\0';
	struct config_check_data ccd;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_CONVENTION_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq('C', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_STYLE_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq('S', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_WARNING_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq('W', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_ERROR_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq('E', severity);

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(SEVERITY_FATAL_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq('F', severity);
}
END_TEST

START_TEST (test_parse_config_checks) {
	char severity = '\0';
	struct string_list *dis = NULL;
	struct string_list *en = NULL;
	struct string_list *cfm = NULL;
	struct config_check_data ccd;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(CHECKS_FILENAME, 0, &severity, &dis, &en, &cfm, &ccd));

	ck_assert_ptr_nonnull(dis);
	ck_assert_str_eq(dis->string, "E-003");
	ck_assert_str_eq(dis->next->string, "E-004");
	ck_assert_ptr_null(dis->next->next);

	ck_assert_ptr_null(en);

	free_string_list(dis);
	dis = NULL;
	free_string_list(en);
	en = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(CHECKS_FILENAME, 1, &severity, &dis, &en, &cfm, &ccd));

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

START_TEST (test_parse_config_ordering_rules) {
	char severity = '\0';
	struct config_check_data ccd;

	ck_assert_int_eq(SELINT_SUCCESS, parse_config(REFPOL_ORDERING_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));

	ck_assert_int_eq(ORDER_REF, ccd.order_conf);
}
END_TEST

START_TEST (test_parse_config_ordering_requires) {

	char severity = '\0';
	struct config_check_data ccd;

	// default
	ck_assert_int_eq(SELINT_SUCCESS, parse_config("", 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq(DECL_BOOL, ccd.order_requires[0]);
	ck_assert_int_eq(DECL_CLASS, ccd.order_requires[1]);
	ck_assert_int_eq(DECL_ROLE, ccd.order_requires[2]);
	ck_assert_int_eq(DECL_ATTRIBUTE_ROLE, ccd.order_requires[3]);
	ck_assert_int_eq(DECL_ATTRIBUTE, ccd.order_requires[4]);
	ck_assert_int_eq(DECL_TYPE, ccd.order_requires[5]);
	ck_assert_int_eq(true, ccd.ordering_requires_same_flavor);

	// custom
	ck_assert_int_eq(SELINT_SUCCESS, parse_config(ORDER_REQUIRES_FILENAME, 0, &severity, NULL, NULL, NULL, &ccd));
	ck_assert_int_eq(DECL_BOOL, ccd.order_requires[0]);
	ck_assert_int_eq(DECL_ATTRIBUTE, ccd.order_requires[1]);
	ck_assert_int_eq(DECL_ATTRIBUTE_ROLE, ccd.order_requires[2]);
	ck_assert_int_eq(DECL_TYPE, ccd.order_requires[3]);
	ck_assert_int_eq(DECL_CLASS, ccd.order_requires[4]);
	ck_assert_int_eq(DECL_ROLE, ccd.order_requires[5]);
	ck_assert_int_eq(false, ccd.ordering_requires_same_flavor);
}
END_TEST

START_TEST (test_bad_configs) {
	char severity = '\0';
	struct string_list *dis = NULL;
	struct string_list *en = NULL;
	struct string_list *cfm = NULL;
	struct config_check_data ccd;

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_FORMAT_1, 0, &severity, &dis, &en, &cfm, &ccd));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_FORMAT_2, 0, &severity, &dis, &en, &cfm, &ccd));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_OPTION, 0, &severity, &dis, &en, &cfm, &ccd));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_SEVERITY, 0, &severity, &dis, &en, &cfm, &ccd));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('\0', severity);

	ck_assert_int_eq(SELINT_CONFIG_PARSE_ERROR, parse_config(BAD_ORDER, 0, &severity, &dis, &en, &cfm, &ccd));
	ck_assert_ptr_null(dis);
	ck_assert_ptr_null(en);
	ck_assert_int_eq('C', severity);
}
END_TEST

Suite *selint_config_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("SELint_config");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_config_severity);
	tcase_add_test(tc_core, test_parse_config_checks);
	tcase_add_test(tc_core, test_parse_config_ordering_rules);
	tcase_add_test(tc_core, test_parse_config_ordering_requires);
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
