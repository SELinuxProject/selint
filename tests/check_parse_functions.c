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
#include <string.h>
#include <stdlib.h>

#include "../src/parse_functions.h"
#include "../src/maps.h"

#define EXAMPLE_TYPE_1 "foo_t"
#define EXAMPLE_TYPE_2 "bar_t"
#define EXAMPLE_TYPE_3 "baz_t"

START_TEST (test_insert_header) {

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_TE_FILE;

	ck_assert_int_eq(SELINT_SUCCESS, insert_header(&cur, "example", HEADER_BARE, 1));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_nonnull(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_int_eq(NODE_HEADER, cur->flavor);
	ck_assert_int_eq(cur->data.h_data->flavor, HEADER_BARE);
	ck_assert_str_eq(cur->data.h_data->module_name, "example");
	ck_assert_int_eq(cur->lineno, 1);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur->prev));

	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_comment) {

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	cur->flavor = NODE_TE_FILE;

	struct policy_node *prev = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_comment(&cur, 12345));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, prev);
	ck_assert_int_eq(cur->flavor, NODE_COMMENT);
	ck_assert_int_eq(cur->lineno, 12345);
	ck_assert_ptr_null(cur->data.str);

	ck_assert_int_eq(SELINT_SUCCESS,free_policy_node(prev));
}
END_TEST

START_TEST (test_insert_declaration) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;
	cur->parent = NULL;
	cur->data.d_data = NULL;
	cur->first_child = NULL;
	cur->next = NULL;

	struct policy_node *prev = cur;

	set_current_module_name("test");

	struct string_list *attrs = calloc(1, sizeof(struct string_list));

	ck_assert_int_eq(SELINT_SUCCESS, insert_declaration(&cur, DECL_TYPE, "foo_t", attrs, 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_eq(cur->prev, prev);
	ck_assert_int_eq(cur->flavor, NODE_DECL);
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(prev->first_child);
	ck_assert_ptr_nonnull(cur->data.d_data);
	ck_assert_int_eq(cur->data.d_data->flavor, DECL_TYPE);
	ck_assert_str_eq(cur->data.d_data->name, "foo_t");
	ck_assert_ptr_eq(cur->data.d_data->attrs, attrs);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(prev));

	// TODO attributes

	const char *mn = look_up_in_decl_map("foo_t", DECL_TYPE);

	ck_assert_ptr_nonnull(mn);

	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_aliases) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_DECL;

	struct policy_node *orig = cur;

	struct string_list *aliases = calloc(1, sizeof(struct string_list));
	aliases->string = strdup("foo_t");
	aliases->next = calloc(1, sizeof(struct string_list));
	aliases->next->string = strdup("bar_t");
	aliases->next->next = NULL;

	set_current_module_name("test");

	ck_assert_int_eq(SELINT_SUCCESS, insert_aliases(&cur, aliases, DECL_TYPE, 123));

	ck_assert_ptr_eq(cur, orig);
	ck_assert_ptr_nonnull(cur->first_child);

	cur = cur->first_child;

	ck_assert_int_eq(cur->flavor, NODE_ALIAS);
	ck_assert_str_eq(cur->data.str, "foo_t");
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_eq(cur->parent, orig);
	ck_assert_ptr_nonnull(cur->next);
	ck_assert_int_eq(cur->lineno, 123);

	cur = cur->next;

	ck_assert_int_eq(cur->flavor, NODE_ALIAS);
	ck_assert_str_eq(cur->data.str, "bar_t");
	ck_assert_ptr_nonnull(cur->prev);
	ck_assert_ptr_eq(cur->parent, orig);
	ck_assert_ptr_null(cur->next);
	ck_assert_int_eq(cur->lineno, 123);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(orig));

	ck_assert_ptr_nonnull(look_up_in_decl_map("foo_t", DECL_TYPE));
	ck_assert_ptr_nonnull(look_up_in_decl_map("bar_t", DECL_TYPE));

	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_type_alias) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *orig = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_type_alias(&cur, "foo_t", 123));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, orig);

	ck_assert_int_eq(cur->flavor, NODE_TYPE_ALIAS);
	ck_assert_int_eq(cur->lineno, 123);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(orig));

	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_av_rule) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_av_rule(&cur, AV_RULE_AUDITALLOW, NULL, NULL, NULL, NULL, 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_AV_RULE, cur->flavor);
	struct av_rule_data *avd = cur->data.av_data;
	ck_assert_int_eq(AV_RULE_AUDITALLOW, avd->flavor);
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_ptr_null(avd->sources);
	ck_assert_ptr_null(avd->targets);
	ck_assert_ptr_null(avd->object_classes);
	ck_assert_ptr_null(avd->perms);

	free_policy_node(head);

	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_role_allow) {

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));

	struct policy_node *head = cur;

	struct string_list *sl1 = sl_from_str("staff_r");
	struct string_list *sl2 = sl_from_str("dbadm_r");

	ck_assert_int_eq(SELINT_SUCCESS, insert_role_allow(&cur, sl1, sl2, 20));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_ROLE_ALLOW, cur->flavor);

	struct role_allow_data *ra = cur->data.ra_data;
	ck_assert_str_eq("staff_r", ra->from->string);
	ck_assert_ptr_null(ra->from->next);
	ck_assert_str_eq("dbadm_r", ra->to->string);
	ck_assert_ptr_null(ra->to->next);

	free_policy_node(head);

	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_type_transition) {
	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_type_transition(&cur, TT_TT, NULL, NULL, NULL, "example_tmp_t", NULL, 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TT_RULE, cur->flavor);
	ck_assert_int_eq(cur->lineno, 1234);
	struct type_transition_data *ttd = cur->data.tt_data;
	ck_assert_ptr_null(ttd->sources);
	ck_assert_ptr_null(ttd->targets);
	ck_assert_ptr_null(ttd->object_classes);
	ck_assert_str_eq("example_tmp_t", ttd->default_type);
	ck_assert_ptr_null(ttd->name);

	free_policy_node(head);

	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_named_type_transition) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_type_transition(&cur, TT_TT, NULL, NULL, NULL, "example_tmp_t", "filename.txt", 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TT_RULE, cur->flavor);
	ck_assert_int_eq(cur->lineno, 1234);
	struct type_transition_data *ttd = cur->data.tt_data;
	ck_assert_ptr_null(ttd->sources);
	ck_assert_ptr_null(ttd->targets);
	ck_assert_ptr_null(ttd->object_classes);
	ck_assert_str_eq("example_tmp_t", ttd->default_type);
	ck_assert_str_eq("filename.txt", ttd->name);

	free_policy_node(head);

	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_interface_call) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	struct policy_node *head = cur;

	struct string_list *args = calloc(1, sizeof(struct string_list));
	args->string = strdup("foo_t");
	args->next = calloc(1, sizeof(struct string_list));
	args->next->string = strdup("bar_t");
	args->next->next = NULL;

	ck_assert_int_eq(SELINT_SUCCESS, insert_interface_call(&cur, "do_things", args, 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_IF_CALL, cur->flavor);
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_nonnull(cur->prev);

	struct if_call_data *if_data = cur->data.ic_data;

	ck_assert_str_eq("do_things", if_data->name);
	ck_assert_str_eq("foo_t", if_data->args->string);
	ck_assert_str_eq("bar_t", if_data->args->next->string);

	free_policy_node(head);
	cleanup_parsing();

}
END_TEST

START_TEST (test_insert_permissive_statement) {
	struct policy_node *cur = calloc(1, sizeof(struct policy_node));

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, insert_permissive_statement(&cur, "unconfined_t", 5678));

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_PERMISSIVE, cur->flavor);
	ck_assert_int_eq(5678, cur->lineno);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_str_eq("unconfined_t", cur->data.str);

	free_policy_node(head);
	cleanup_parsing();
}
END_TEST

START_TEST (test_optional_policy) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_optional_policy(&cur, 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_nonnull(cur->parent);
	ck_assert_ptr_eq(cur->parent->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_START_BLOCK);
	ck_assert_int_eq(cur->parent->flavor, NODE_OPTIONAL_POLICY);
	ck_assert_ptr_eq(cur->parent->first_child, cur);
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_int_eq(cur->parent->lineno, 1234);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(cur->parent->next);

	ck_assert_int_eq(SELINT_SUCCESS, end_optional_policy(&cur));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_OPTIONAL_POLICY);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_ptr_null(cur->first_child->prev);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();
}
END_TEST

START_TEST (test_interface_def) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	set_current_module_name("test");

	ck_assert_int_eq(SELINT_SUCCESS, begin_interface_def(&cur, NODE_INTERFACE_DEF, "foo_read_conf", 1234));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_nonnull(cur->parent);
	ck_assert_ptr_eq(cur->parent->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_START_BLOCK);
	ck_assert_int_eq(cur->parent->flavor, NODE_INTERFACE_DEF);
	ck_assert_ptr_eq(cur->parent->first_child, cur);
	ck_assert_str_eq(cur->parent->data.str, "foo_read_conf");
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_int_eq(cur->parent->lineno, 1234);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_ptr_null(cur->parent->next);

	ck_assert_int_eq(SELINT_SUCCESS, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_BAD_ARG, begin_interface_def(&cur, NODE_DECL, "foo_read_conf", 2345));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_int_eq(cur->flavor, NODE_INTERFACE_DEF);
	ck_assert_int_eq(cur->lineno, 1234);
	ck_assert_ptr_nonnull(cur->first_child);
	ck_assert_int_eq(cur->first_child->lineno, 1234);
	ck_assert_ptr_null(cur->first_child->prev);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();
}
END_TEST

START_TEST (test_wrong_block_end) {

	struct policy_node *cur = malloc(sizeof(struct policy_node));
	memset(cur, 0, sizeof(struct policy_node));

	cur->flavor = NODE_TE_FILE;

	struct policy_node *head = cur;

	set_current_module_name("test");

	ck_assert_int_eq(SELINT_SUCCESS, begin_optional_policy(&cur, 1234));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, begin_interface_def(&cur, NODE_INTERFACE_DEF, "sample_interface", 1235));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_optional_policy(&cur));

	ck_assert_int_eq(SELINT_NOT_IN_BLOCK, end_gen_require(&cur, 0));

	ck_assert_int_eq(SELINT_SUCCESS, end_interface_def(&cur));

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(head));

	cleanup_parsing();

}
END_TEST

START_TEST (test_save_command) {

	struct policy_node *cur = calloc(1, sizeof(struct policy_node));
	ck_assert_int_eq(SELINT_BAD_ARG, save_command(NULL, "foo"));
	ck_assert_int_eq(SELINT_SUCCESS, save_command(cur, NULL));

	ck_assert_int_eq(SELINT_PARSE_ERROR, save_command(cur, "foo"));

	ck_assert_int_eq(SELINT_PARSE_ERROR, save_command(cur, "selint-fake:W-001"));

	ck_assert_ptr_null(cur->exceptions);
	ck_assert_int_eq(SELINT_SUCCESS, save_command(cur, "selint-disable:W-001"));
	ck_assert_str_eq("W-001", cur->exceptions);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur));
	cleanup_parsing();
}
END_TEST

START_TEST (test_insert_type_attribute) {

	struct policy_node *head = calloc(1, sizeof(struct policy_node));

	struct policy_node *cur = head;

	struct string_list *attrs = calloc(1, sizeof(struct string_list));
	attrs->string = strdup("foo");

	ck_assert_int_eq(SELINT_SUCCESS, insert_type_attribute(&cur, "foo_t", attrs, 1234));

	ck_assert_ptr_eq(cur->prev, head);
	ck_assert_str_eq(cur->data.at_data->type, "foo_t");
	ck_assert_str_eq(cur->data.at_data->attrs->string, "foo");

	free_policy_node(head);
	cleanup_parsing();

}
END_TEST

static Suite *parse_functions_suite(void) {
	Suite *s;
	TCase *tc_core, *tc_blocks;

	s = suite_create("Parse_Functions");

	tc_core = tcase_create("Core");
	tc_blocks = tcase_create("Blocks");

	tcase_add_test(tc_core, test_insert_header);
	tcase_add_test(tc_core, test_insert_comment);
	tcase_add_test(tc_core, test_insert_declaration);
	tcase_add_test(tc_core, test_insert_aliases);
	tcase_add_test(tc_core, test_insert_type_alias);
	tcase_add_test(tc_core, test_insert_av_rule);
	tcase_add_test(tc_core, test_insert_role_allow);
	tcase_add_test(tc_core, test_insert_type_transition);
	tcase_add_test(tc_core, test_insert_named_type_transition);
	tcase_add_test(tc_core, test_insert_interface_call);
	tcase_add_test(tc_core, test_insert_permissive_statement);
	tcase_add_test(tc_core, test_save_command);
	tcase_add_test(tc_core, test_insert_type_attribute);
	suite_add_tcase(s, tc_core);

	tcase_add_test(tc_blocks, test_optional_policy);
	tcase_add_test(tc_blocks, test_interface_def);
	tcase_add_test(tc_blocks, test_wrong_block_end);
	suite_add_tcase(s, tc_blocks);

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
