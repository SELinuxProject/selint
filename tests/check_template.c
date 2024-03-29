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
#include <stdlib.h>
#include <stdio.h>

#include "../src/parse_functions.h"
#include "../src/template.h"
#include "../src/parse.h"
#include "../src/maps.h"

#define POLICIES_DIR SAMPLE_POL_DIR
#define NESTED_IF_FILENAME POLICIES_DIR "nested_templates.if"
#define DECLARING_IF_FILENAME POLICIES_DIR "declaring_template.if"
#define DECLARING_TE_FILENAME POLICIES_DIR "declaring_template.te"

START_TEST (test_replace_m4) {
	const char *orig1 = "$1_t";

	struct string_list *args = calloc(1,sizeof(struct string_list));
	args->string = strdup("foo");
	args->next = calloc(1,sizeof(struct string_list));
	args->next->string = strdup("bar");
	args->next->next = NULL;

	char *res = replace_m4(orig1, args);

	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("foo_t", res);

	free(res);

	const char *orig2 = "$2";

	res = replace_m4(orig2, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("bar", res);

	free(res);

	const char *orig3 = "test_$1_test";

	res = replace_m4(orig3, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("test_foo_test", res);

	free(res);

	const char *orig4 = "test$2$1";

	res = replace_m4(orig4, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("testbarfoo", res);

	free(res);

	free_string_list(args);

}
END_TEST

START_TEST (test_replace_m4_too_few_args) {
	struct string_list *args = calloc(1,sizeof(struct string_list));
	args->string = strdup("foo");
	args->next = calloc(1,sizeof(struct string_list));
	args->next->string = strdup("bar");
	args->next->next = NULL;

	const char *orig = "$3_t";

	char *ret = replace_m4(orig, args);

	ck_assert_ptr_nonnull(ret);
	ck_assert_str_eq("_t", ret);

	free_string_list(args);
	free(ret);

}
END_TEST

START_TEST (test_replace_m4_nothing_to_replace) {
	struct string_list *args = calloc(1, sizeof(struct string_list));
	args->string = strdup("foo");

	const char *orig = "bar_t";

	char *res = replace_m4(orig, args);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("bar_t", res);

	free(res);
	free_string_list(args);
}
END_TEST

START_TEST (test_replace_m4_bad_dollar_sign) {
	struct string_list *args = calloc(1, sizeof(struct string_list));
	args->string = strdup("foo");

	const char *orig = "$string";

	ck_assert_ptr_null(replace_m4(orig, args));

	free_string_list(args);
}
END_TEST

START_TEST (test_replace_m4_list) {

	struct string_list *caller_args = calloc(1,sizeof(struct string_list));
	caller_args->string = strdup("foo");
	caller_args->next = calloc(1,sizeof(struct string_list));
	caller_args->next->string = strdup("bar");
	caller_args->next->next = NULL;

	struct string_list *called_args = calloc(1,sizeof(struct string_list));
	called_args->string = strdup("$2");
	called_args->next = calloc(1,sizeof(struct string_list));
	called_args->next->string = strdup("$1");
	called_args->next->next = NULL;

	struct string_list *ret = replace_m4_list(caller_args, called_args);

	ck_assert_ptr_nonnull(ret);
	ck_assert_str_eq(ret->string, "bar");
	ck_assert_ptr_nonnull(ret->next);
	ck_assert_str_eq(ret->next->string, "foo");
	ck_assert_ptr_null(ret->next->next);

	free_string_list(caller_args);
	free_string_list(called_args);
	free_string_list(ret);

}
END_TEST

START_TEST (test_replace_m4_list_too_few_args) {

	struct string_list *caller_args = calloc(1,sizeof(struct string_list));
	caller_args->string = strdup("foo");
	struct string_list *called_args = calloc(1,sizeof(struct string_list));
	called_args->string = strdup("$5");

	struct string_list *ret = replace_m4_list(caller_args, called_args);
	ck_assert_ptr_nonnull(ret);
	ck_assert_ptr_nonnull(ret->string);
	ck_assert_str_eq("", ret->string);

	free_string_list(caller_args);
	free_string_list(called_args);
	free_string_list(ret);
}
END_TEST

START_TEST (test_nested_template_declarations) {

	set_current_module_name("nested");

	FILE *f = fopen(NESTED_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, NESTED_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast);
	fclose(f);

	struct string_list *called_args = calloc(1,sizeof(struct string_list));
	called_args->string = strdup("first");
	called_args->next = calloc(1,sizeof(struct string_list));
	called_args->next->string = strdup("second");
	called_args->next->next = calloc(1,sizeof(struct string_list));
	called_args->next->next->string = strdup("third");
	called_args->next->next->next = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, add_template_declarations("outer", called_args, NULL, "nested_interfaces"));

	ck_assert_str_eq("nested_interfaces", look_up_in_decl_map("first_t", DECL_TYPE));
	ck_assert_str_eq("nested_interfaces", look_up_in_decl_map("third_foo_t", DECL_TYPE));
	ck_assert_str_eq("nested_interfaces", look_up_in_decl_map("second_bar_t", DECL_TYPE));
	ck_assert_ptr_null(look_up_in_decl_map("second_foo_t", DECL_TYPE));
	ck_assert_ptr_null(look_up_in_decl_map("third_bar_t", DECL_TYPE));

	free_string_list(called_args);
	free_policy_node(ast);
	cleanup_parsing();

}
END_TEST

START_TEST (test_declaring_template) {

	// setup
	set_current_module_name("declaring_template_if");

	FILE *f_if = fopen(DECLARING_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f_if);
	struct policy_node *ast_if = yyparse_wrapper(f_if, DECLARING_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast_if);
	fclose(f_if);

	set_current_module_name("declaring_template_te");

	FILE *f_te = fopen(DECLARING_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f_te);
	struct policy_node *ast_te = yyparse_wrapper(f_te, DECLARING_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast_te);
	fclose(f_te);

	// checks
	const char *mod_name;

	ck_assert_uint_eq(4, decl_map_count(DECL_TYPE));
	mod_name = look_up_in_decl_map("prefix_foo_suffix", DECL_TYPE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	mod_name = look_up_in_decl_map("bar_t", DECL_TYPE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	mod_name = look_up_in_decl_map("prefix_good_suffix", DECL_TYPE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	mod_name = look_up_in_decl_map("morning_t", DECL_TYPE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	// these are called via an interface so it isn't declared
	mod_name = look_up_in_decl_map("prefix_hello_suffix", DECL_TYPE);
	ck_assert_ptr_null(mod_name);
	mod_name = look_up_in_decl_map("world_t", DECL_TYPE);
	ck_assert_ptr_null(mod_name);

	ck_assert_uint_eq(2, decl_map_count(DECL_ROLE));
	mod_name = look_up_in_decl_map("bar_r", DECL_ROLE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	mod_name = look_up_in_decl_map("morning_r", DECL_ROLE);
	ck_assert_str_eq("declaring_template_te", mod_name);
	// this is called via an interface so it isn't declared
	mod_name = look_up_in_decl_map("world_t", DECL_TYPE);
	ck_assert_ptr_null(mod_name);

	// cleanup
	free_policy_node(ast_te);
	free_policy_node(ast_if);
	cleanup_parsing();

}
END_TEST

static Suite *template_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Template");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_replace_m4);
	tcase_add_test(tc_core, test_replace_m4_too_few_args);
	tcase_add_test(tc_core, test_replace_m4_nothing_to_replace);
	tcase_add_test(tc_core, test_replace_m4_bad_dollar_sign);
	tcase_add_test(tc_core, test_replace_m4_list);
	tcase_add_test(tc_core, test_replace_m4_list_too_few_args);
	tcase_add_test(tc_core, test_nested_template_declarations);
	tcase_add_test(tc_core, test_declaring_template);
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
