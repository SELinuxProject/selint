/*
* Copyright 2021 The SELint Contributors
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
#include <stdio.h>

#include "../src/tree.h"
#include "../src/parse.h"
#include "../src/parse_functions.h"

#define POLICIES_DIR SAMPLE_POL_DIR
#define CONFLICT_INFER_IF POLICIES_DIR "infer_conflict.if"
#define SIMPLE_INFER_IF POLICIES_DIR "infer_simple.if"
#define INFER_LOOP_IF POLICIES_DIR "infer_loop.if"

extern enum selint_error infer_interfaces_deep(const struct policy_node *node);
extern enum selint_error infer_interfaces_shallow(const struct policy_node *node);

START_TEST (test_infer_simple) {

	// setup
	set_current_module_name("infer_simple");

	FILE *f = fopen(SIMPLE_INFER_IF, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, SIMPLE_INFER_IF, NODE_IF_FILE);
	fclose(f);
	ck_assert_ptr_nonnull(ast);

	ck_assert_int_eq(SELINT_SUCCESS, infer_interfaces_shallow(ast));

	// actual checks
	const struct interface_trait *if_trait;

	// sample_infer_typeorattribute1
	if_trait = look_up_in_if_traits_map("sample_infer_typeorattribute1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_typeorattribute1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_typeorattribute2
	if_trait = look_up_in_if_traits_map("sample_infer_typeorattribute2");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_typeorattribute2", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_unknown1
	if_trait = look_up_in_if_traits_map("sample_infer_unknown1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_unknown1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(false, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_UNKNOWN, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_temp1
	if_trait = look_up_in_if_traits_map("sample_infer_temp1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_temp1", if_trait->name);
	ck_assert_int_eq(TEMPLATE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TEXT, if_trait->parameters[0]);
	ck_assert_int_eq(PARAM_ROLE, if_trait->parameters[1]);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[2]);
	for (int i = 3; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_redirect_if
	if_trait = look_up_in_if_traits_map("sample_redirect_if");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_redirect_if", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	ck_assert_int_eq(SELINT_SUCCESS, infer_interfaces_deep(ast));

	// sample_infer_typeorattribute1
	if_trait = look_up_in_if_traits_map("sample_infer_typeorattribute1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_typeorattribute1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_typeorattribute2
	if_trait = look_up_in_if_traits_map("sample_infer_typeorattribute2");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_typeorattribute2", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_unknown1
	if_trait = look_up_in_if_traits_map("sample_infer_unknown1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_unknown1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_temp1
	if_trait = look_up_in_if_traits_map("sample_infer_temp1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_temp1", if_trait->name);
	ck_assert_int_eq(TEMPLATE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TEXT, if_trait->parameters[0]);
	ck_assert_int_eq(PARAM_ROLE, if_trait->parameters[1]);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[2]);
	for (int i = 3; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_redirect_if
	if_trait = look_up_in_if_traits_map("sample_redirect_if");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_redirect_if", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_TYPE_OR_ATTRIBUTE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// cleanup
	free_policy_node(ast);

	cleanup_parsing();

}
END_TEST

START_TEST (test_infer_loop) {

	// setup
	set_current_module_name("infer_loop");

	FILE *f = fopen(INFER_LOOP_IF, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, INFER_LOOP_IF, NODE_IF_FILE);
	fclose(f);
	ck_assert_ptr_nonnull(ast);

	ck_assert_int_eq(SELINT_SUCCESS, infer_interfaces_shallow(ast));

	const struct interface_trait *if_trait;

	// sample_infer_loop1
	if_trait = look_up_in_if_traits_map("sample_infer_loop1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_loop1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(false, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_UNKNOWN, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_loop2
	if_trait = look_up_in_if_traits_map("sample_infer_loop2");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_loop2", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(false, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_UNKNOWN, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	ck_assert_int_eq(SELINT_IF_CALL_LOOP, infer_interfaces_deep(ast));

	// sample_infer_loop1
	if_trait = look_up_in_if_traits_map("sample_infer_loop1");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_loop1", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(false, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_UNKNOWN, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// sample_infer_loop2
	if_trait = look_up_in_if_traits_map("sample_infer_loop2");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("sample_infer_loop2", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(false, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_UNKNOWN, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// cleanup
	free_policy_node(ast);

	cleanup_parsing();

}
END_TEST

START_TEST (test_infer_conflict) {

	// setup
	set_current_module_name("infer_conflict");

	FILE *f = fopen(CONFLICT_INFER_IF, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, CONFLICT_INFER_IF, NODE_IF_FILE);
	fclose(f);
	ck_assert_ptr_nonnull(ast);

	ck_assert_int_eq(SELINT_SUCCESS, infer_interfaces_shallow(ast));

	const struct interface_trait *if_trait;

	// conflict_infer
	if_trait = look_up_in_if_traits_map("conflict_infer");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("conflict_infer", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_ROLE, if_trait->parameters[0]);  // TODO: report conflict, not PARAM_ROLE
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	ck_assert_int_eq(SELINT_SUCCESS, infer_interfaces_deep(ast));

	// conflict_infer
	if_trait = look_up_in_if_traits_map("conflict_infer");
	ck_assert_ptr_nonnull(if_trait);
	ck_assert_str_eq("conflict_infer", if_trait->name);
	ck_assert_int_eq(INTERFACE_TRAIT, if_trait->type);
	ck_assert_int_eq(true, if_trait->is_inferred);
	ck_assert_int_eq(PARAM_ROLE, if_trait->parameters[0]);
	for (int i = 1; i < TRAIT_MAX_PARAMETERS; ++i) ck_assert_int_eq(PARAM_INITIAL, if_trait->parameters[i]);
	ck_assert_ptr_nonnull(if_trait->node);

	// cleanup
	free_policy_node(ast);

	cleanup_parsing();

}
END_TEST

static Suite *parsing_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Infer");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_infer_simple);
	tcase_add_test(tc_core, test_infer_loop);
	tcase_add_test(tc_core, test_infer_conflict);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed;
	Suite *s;
	SRunner *sr;

	s = parsing_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? 0 : -1;
}
