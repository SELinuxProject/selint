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
#include <stdio.h>

#include "../src/tree.h"
#include "../src/parse_fc.h"

#define POLICIES_DIR SAMPLE_POL_DIR
#define BASIC_FC_FILENAME POLICIES_DIR "basic.fc"
#define WITH_M4_FILENAME POLICIES_DIR "with_m4.fc"
#define NONE_CONTEXT_FILENAME POLICIES_DIR "none_context.fc"

START_TEST (test_parse_context) {

	char context_str[] = "staff_u:staff_r:foo_t";

	struct sel_context *ctx = parse_context(context_str);

	ck_assert_ptr_nonnull(ctx);
	ck_assert_str_eq("staff_u", ctx->user);
	ck_assert_str_eq("staff_r", ctx->role);
	ck_assert_str_eq("foo_t", ctx->type);
	ck_assert_ptr_null(ctx->range);
	ck_assert_int_eq(0, ctx->has_gen_context);

	free_sel_context(ctx);

}
END_TEST

START_TEST (test_parse_context_missing_field) {

	char context_str[] = "staff_u:foo_t";

	struct sel_context *ctx = parse_context(context_str);

	ck_assert_ptr_null(ctx);

}
END_TEST

START_TEST (test_parse_fc_line_with_gen_context) {
	char line[] = "/usr/bin(/.*)?		gen_context(system_u:object_r:bin_t, s0)";

	struct fc_entry *out= parse_fc_line(line);

	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq("/usr/bin(/.*)?", out->path);
	ck_assert(out->obj == '\0');
	ck_assert_ptr_nonnull(out->context);
	ck_assert_int_eq(1, out->context->has_gen_context);
	ck_assert_str_eq("system_u", out->context->user);
	ck_assert_str_eq("object_r", out->context->role);
	ck_assert_str_eq("bin_t", out->context->type);
	ck_assert_str_eq("s0", out->context->range);

	free_fc_entry(out);

}
END_TEST

START_TEST (test_parse_fc_line) {
	char line[] = "/usr/bin(/.*)?		system_u:object_r:bin_t:s0";

	struct fc_entry *out= parse_fc_line(line);

	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq("/usr/bin(/.*)?", out->path);
	ck_assert(out->obj == '\0');
	ck_assert_ptr_nonnull(out->context);
	ck_assert_int_eq(0, out->context->has_gen_context);
	ck_assert_str_eq("system_u", out->context->user);
	ck_assert_str_eq("object_r", out->context->role);
	ck_assert_str_eq("bin_t", out->context->type);
	ck_assert_str_eq("s0", out->context->range);

	free_fc_entry(out);

}
END_TEST

START_TEST (test_parse_fc_line_with_obj) {
	char line[] = "/usr/bin(/.*)?		-d	system_u:object_r:bin_t:s0";

	struct fc_entry *out= parse_fc_line(line);

	ck_assert_ptr_nonnull(out);
	ck_assert_str_eq("/usr/bin(/.*)?", out->path);
	ck_assert(out->obj == 'd');
	ck_assert_ptr_nonnull(out->context);
	ck_assert_int_eq(0, out->context->has_gen_context);
	ck_assert_str_eq("system_u", out->context->user);
	ck_assert_str_eq("object_r", out->context->role);
	ck_assert_str_eq("bin_t", out->context->type);
	ck_assert_str_eq("s0", out->context->range);

	free_fc_entry(out);
}
END_TEST

START_TEST (test_parse_basic_fc_file) {
	struct policy_node *ast = parse_fc_file(BASIC_FC_FILENAME);

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(ast->flavor, NODE_FC_FILE);
	ck_assert_ptr_nonnull(ast->next);

	struct policy_node *cur = ast->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_ERROR);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_null(cur->next);

	free_policy_node(ast);
}
END_TEST

START_TEST (test_parse_m4) {
	struct policy_node *ast = parse_fc_file(WITH_M4_FILENAME);

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(ast->flavor, NODE_FC_FILE);
	ck_assert_ptr_nonnull(ast->next);

	struct policy_node *cur = ast->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_nonnull(cur->data.fc_data);

	struct fc_entry *data = cur->data.fc_data;

	ck_assert_ptr_nonnull(data->context);
	ck_assert_str_eq(data->context->type, "hijklmn_t");

	ck_assert_ptr_null(cur->next);

	free_policy_node(ast);
}
END_TEST

START_TEST (test_parse_none_context) {
	struct policy_node *ast = parse_fc_file(NONE_CONTEXT_FILENAME);

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(ast->flavor, NODE_FC_FILE);
	ck_assert_ptr_nonnull(ast->next);

	struct policy_node *cur = ast->next;

	ck_assert_int_eq(cur->flavor, NODE_FC_ENTRY);
	ck_assert_ptr_null(cur->next);

	struct fc_entry *data = cur->data.fc_data;

	ck_assert_ptr_null(data->context);

	free_policy_node(ast);
}
END_TEST


Suite *parse_fc_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parse_fc");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_context);
	tcase_add_test(tc_core, test_parse_context_missing_field);
	tcase_add_test(tc_core, test_parse_fc_line_with_gen_context);
	tcase_add_test(tc_core, test_parse_fc_line);
	tcase_add_test(tc_core, test_parse_fc_line_with_obj);
	tcase_add_test(tc_core, test_parse_basic_fc_file);
	tcase_add_test(tc_core, test_parse_m4);
	tcase_add_test(tc_core, test_parse_none_context);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = parse_fc_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
