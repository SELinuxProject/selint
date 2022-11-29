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
#include "../src/parse.h"
#include "../src/parse_functions.h"

#define POLICIES_DIR SAMPLE_POL_DIR
#define BASIC_TE_FILENAME POLICIES_DIR "basic.te"
#define BASIC_IF_FILENAME POLICIES_DIR "basic.if"
#define UNCOMMON_TE_FILENAME POLICIES_DIR "uncommon.te"
#define IFDEF_IF_FILENAME POLICIES_DIR "ifdef.if"
#define BLOCKS_TE_FILENAME POLICIES_DIR "blocks.te"
#define EMPTY_TE_FILENAME POLICIES_DIR "empty.te"
#define SYNTAX_ERROR_FILENAME POLICIES_DIR "syntax_error.te"
#define BAD_RA_FILENAME POLICIES_DIR "bad_role_allow.te"
#define DISABLE_BOOLTUNABLE_TE_FILENAME POLICIES_DIR "disable_booltunable.te"
#define DISABLE_COMMENT_TE_FILENAME POLICIES_DIR "disable_comment.te"
#define DISABLE_COMMENT_IF_FILENAME POLICIES_DIR "disable_comment.if"
#define DISABLE_REQUIRE_IF_FILENAME POLICIES_DIR "disable_require.if"
#define BOOL_DECLARATION_FILENAME POLICIES_DIR "bool_declarations.te"
#define EXTENDED_TE_FILENAME POLICIES_DIR "extended_perms.te"
#define IFDEF_BLOCK_FILENAME POLICIES_DIR "ifdef_block.te"

START_TEST (test_parse_basic_te) {

	set_current_module_name("basic");

	FILE *f = fopen(BASIC_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, BASIC_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	struct policy_node *current = ast;

	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_TE_FILE, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = ast->next;
	ck_assert_int_eq(NODE_HEADER, current->flavor);
	struct header_data *hd = current->data.h_data;
	ck_assert_int_eq(HEADER_MACRO, hd->flavor);
	ck_assert_str_eq("basic", hd->module_name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	struct declaration_data *dd = current->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_t", dd->name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	dd = current->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_exec_t", dd->name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_IF_CALL, current->flavor);
	struct if_call_data *icd = current->data.ic_data;
	ck_assert_str_eq("macro1", icd->name);
	struct string_list *args = icd->args;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_null(args->next);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_IF_CALL, current->flavor);
	icd = current->data.ic_data;
	ck_assert_str_eq("macro2", icd->name);
	args = icd->args;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("basic_exec_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_null(args->next);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_IF_CALL, current->flavor);
	icd = current->data.ic_data;
	ck_assert_str_eq("macro3", icd->name);
	args = icd->args;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("basic_exec_t", args->string);
	ck_assert_int_eq(1, args->has_incorrect_space);
	ck_assert_int_eq(0, args->arg_start);
	ck_assert_ptr_null(args->next);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_IF_CALL, current->flavor);
	icd = current->data.ic_data;
	ck_assert_str_eq("macro4", icd->name);
	args = icd->args;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("basic_exec_t", args->string);
	ck_assert_int_eq(1, args->has_incorrect_space);
	ck_assert_int_eq(0, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("basic_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(1, args->arg_start);
	ck_assert_ptr_nonnull(args->next);
	args = args->next;
	ck_assert_str_eq("-basic_exec_t", args->string);
	ck_assert_int_eq(0, args->has_incorrect_space);
	ck_assert_int_eq(0, args->arg_start);
	ck_assert_ptr_null(args->next);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_OPTIONAL_POLICY, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->first_child);

	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);

	ck_assert_str_eq("basic", look_up_in_decl_map("basic_t", DECL_TYPE));
	ck_assert_int_eq(2, decl_map_count(DECL_TYPE));

	free_policy_node(ast);

	cleanup_parsing();

	fclose(f);

}
END_TEST

START_TEST (test_parse_basic_if) {

	set_current_module_name("basic");

	FILE *f = fopen(BASIC_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, BASIC_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast);

	struct policy_node *current = ast;

	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_IF_FILE, current->flavor);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_COMMENT, current->flavor);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_COMMENT, current->flavor);
	ck_assert_ptr_nonnull(current->next);


	current = current->next;

	ck_assert_int_eq(NODE_INTERFACE_DEF, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_str_eq("basic_domtrans", current->data.str);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(current->flavor, NODE_GEN_REQ);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_str_eq("basic_t", current->data.d_data->name);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_nonnull(current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_str_eq("basic_exec_t", current->data.d_data->name);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_nonnull(current->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_IF_CALL, current->flavor);
	ck_assert_ptr_nonnull(current->parent);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_parse_uncommon_constructs) {

	set_current_module_name("uncommon");

	FILE *f = fopen(UNCOMMON_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, UNCOMMON_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_ptr_nonnull(ast);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);
}
END_TEST

START_TEST (test_parse_interface_ifdef) {

	set_current_module_name("ifdef");

	FILE *f = fopen(IFDEF_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, IFDEF_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_ptr_nonnull(ast);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);
}
END_TEST

START_TEST (test_parse_blocks) {

	set_current_module_name("blocks");

	FILE *f = fopen(BLOCKS_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, BLOCKS_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_ptr_nonnull(ast);

	struct policy_node *current = ast;

	ck_assert_int_eq(NODE_TE_FILE, current->flavor);

	ck_assert_ptr_nonnull(current->next);

	current = current->next;
	ck_assert_int_eq(NODE_HEADER, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_OPTIONAL_POLICY, current->flavor);
	ck_assert_ptr_null(current->next);
	ck_assert_ptr_nonnull(current->first_child);

	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->next);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);
}
END_TEST

START_TEST (test_parse_empty_file) {

	set_current_module_name("empty");

	FILE *f = fopen(EMPTY_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, EMPTY_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_int_eq(NODE_EMPTY, ast->flavor);
	ck_assert_ptr_null(ast->next);
	ck_assert_ptr_null(ast->first_child);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_syntax_error) {

	set_current_module_name("syntax_error");

	FILE *f = fopen(SYNTAX_ERROR_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	ck_assert_ptr_null(yyparse_wrapper(f, SYNTAX_ERROR_FILENAME, NODE_TE_FILE));

	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_parse_bad_role_allow) {

	set_current_module_name("bad_ra");

	FILE *f = fopen(BAD_RA_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	ck_assert_ptr_null(yyparse_wrapper(f, BAD_RA_FILENAME, NODE_TE_FILE));

	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_disable_booltunable_te) {

	set_current_module_name("disable_booltunable");

	FILE *f = fopen(DISABLE_BOOLTUNABLE_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, DISABLE_BOOLTUNABLE_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	const struct policy_node *cur = ast;

	ck_assert_ptr_nonnull(cur);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_HEADER, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_DECL, cur->flavor);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_TUNABLE_POLICY, cur->flavor);
	ck_assert_str_eq("C-008", cur->exceptions);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_TUNABLE_POLICY, cur->flavor);
	ck_assert_str_eq("C-008", cur->exceptions);
	ck_assert_ptr_nonnull(cur->next);

	cur = cur->next;
	ck_assert_int_eq(NODE_BOOLEAN_POLICY, cur->flavor);
	ck_assert_str_eq("C-008", cur->exceptions);
	ck_assert_ptr_null(cur->next);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_disable_comment_te) {

	set_current_module_name("disable_comment");

	FILE *f = fopen(DISABLE_COMMENT_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, DISABLE_COMMENT_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(NODE_TE_FILE, ast->flavor);
	ck_assert_ptr_nonnull(ast->next);
	ck_assert_int_eq(NODE_HEADER, ast->next->flavor);
	ck_assert_ptr_nonnull(ast->next->next);
	ck_assert_int_eq(NODE_DECL, ast->next->next->flavor);
	ck_assert_ptr_nonnull(ast->next->next->next);
	ck_assert_int_eq(NODE_AV_RULE, ast->next->next->next->flavor);
	ck_assert_str_eq("W-001", ast->next->next->next->exceptions);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_disable_comment_if) {

	set_current_module_name("disable_comment");

	FILE *f = fopen(DISABLE_COMMENT_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, DISABLE_COMMENT_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast);

	ck_assert_ptr_nonnull(ast);
	ck_assert_int_eq(NODE_IF_FILE, ast->flavor);
	ck_assert_ptr_nonnull(ast->next);
	ck_assert_int_eq(NODE_INTERFACE_DEF, ast->next->flavor);
	ck_assert_str_eq("S-012", ast->next->exceptions);
	ck_assert_ptr_null(ast->next->next);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_disable_require_if) {

	set_current_module_name("disable_require");

	FILE *f = fopen(DISABLE_REQUIRE_IF_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, DISABLE_REQUIRE_IF_FILENAME, NODE_IF_FILE);
	ck_assert_ptr_nonnull(ast);

	const struct policy_node *current = ast;

	// top file node
	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_IF_FILE, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_nonnull(current->next);

	// first interface
	current = current->next;
	ck_assert_int_eq(NODE_INTERFACE_DEF, current->flavor);
	ck_assert_str_eq("foo1", current->data.str);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_nonnull(current->first_child);

	// start block
	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// require block
	current = current->next;
	ck_assert_int_eq(NODE_GEN_REQ, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->next);
	ck_assert_ptr_nonnull(current->first_child);

	// start block
	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// first declaration
	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_int_eq(DECL_CLASS, current->data.d_data->flavor);
	ck_assert_str_eq("bar1_c", current->data.d_data->name);
	ck_assert_ptr_nonnull(current->data.d_data->attrs);
	ck_assert_str_eq(" W-010", current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// second declaration
	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_int_eq(DECL_ROLE, current->data.d_data->flavor);
	ck_assert_str_eq("bar1_r", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);
	ck_assert_str_eq(" W-011", current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// third declaration
	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("bar1_b", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);
	ck_assert_str_eq(" W-012", current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_null(current->next);

	// second interface
	current = current->parent->parent->next;
	ck_assert_int_eq(NODE_INTERFACE_DEF, current->flavor);
	ck_assert_str_eq("foo2", current->data.str);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_nonnull(current->first_child);

	// start block
	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// require block
	current = current->next;
	ck_assert_int_eq(NODE_GEN_REQ, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->next);
	ck_assert_ptr_nonnull(current->first_child);

	// start block
	current = current->first_child;
	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// first declaration
	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_int_eq(DECL_TYPE, current->data.d_data->flavor);
	ck_assert_str_eq("bar3_t", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);
	ck_assert_str_eq(" W-011", current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	// second declaration
	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_int_eq(DECL_TYPE, current->data.d_data->flavor);
	ck_assert_str_eq("bar4_t", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);
	ck_assert_str_eq(" W-011", current->exceptions);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_null(current->next);

	// cleanup
	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_bool_declarations) {

	set_current_module_name("bool_declarations");

	FILE *f = fopen(BOOL_DECLARATION_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, BOOL_DECLARATION_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	struct policy_node *current = ast;

	// top file node
	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_TE_FILE, current->flavor);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	// header node
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_HEADER, current->flavor);

	current = current->next;

	// first bool
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_ptr_nonnull(current->data.d_data);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("bool_one", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);

	current = current->next;

	// second bool
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_ptr_nonnull(current->data.d_data);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("bool_two", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);

	current = current->next;

	// third bool
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_ptr_nonnull(current->data.d_data);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("bool_three", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);

	current = current->next;

	// first tunable
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_ptr_nonnull(current->data.d_data);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("tunable_one", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);

	current = current->next;

	// second tunable
	ck_assert_ptr_null(current->parent);
	ck_assert_ptr_null(current->next); // last node
	ck_assert_ptr_nonnull(current->prev);
	ck_assert_ptr_null(current->first_child);
	ck_assert_int_eq(NODE_DECL, current->flavor);
	ck_assert_ptr_nonnull(current->data.d_data);
	ck_assert_int_eq(DECL_BOOL, current->data.d_data->flavor);
	ck_assert_str_eq("tunable_two", current->data.d_data->name);
	ck_assert_ptr_null(current->data.d_data->attrs);

	// check storage
	const char *mod_name;

	mod_name = look_up_in_decl_map("bool_one", DECL_BOOL);
	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq("bool_declarations", mod_name);

	mod_name = look_up_in_decl_map("bool_two", DECL_BOOL);
	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq("bool_declarations", mod_name);

	mod_name = look_up_in_decl_map("bool_three", DECL_BOOL);
	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq("bool_declarations", mod_name);

	mod_name = look_up_in_decl_map("tunable_one", DECL_BOOL);
	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq("bool_declarations", mod_name);

	mod_name = look_up_in_decl_map("tunable_two", DECL_BOOL);
	ck_assert_ptr_nonnull(mod_name);
	ck_assert_str_eq("bool_declarations", mod_name);

	// some cross checks
	ck_assert_ptr_null(look_up_in_decl_map("bool_four", DECL_BOOL));
	ck_assert_ptr_null(look_up_in_decl_map("bool_one", DECL_TYPE));

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);
}
END_TEST

START_TEST (test_file_flavor_mismatch) {

	set_current_module_name("basic");

	FILE *f = fopen(BASIC_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	ck_assert_ptr_null(yyparse_wrapper(f, BASIC_TE_FILENAME, NODE_IF_FILE));

	cleanup_parsing();
	fclose(f);

}
END_TEST

START_TEST (test_extended_perms) {

	set_current_module_name("extended_perms");

	FILE *f = fopen(EXTENDED_TE_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, EXTENDED_TE_FILENAME, NODE_TE_FILE);
	ck_assert_ptr_nonnull(ast);

	struct policy_node *current = ast;

	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_TE_FILE, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = ast->next;
	ck_assert_int_eq(NODE_HEADER, current->flavor);
	struct header_data *hd = current->data.h_data;
	ck_assert_int_eq(HEADER_MACRO, hd->flavor);
	ck_assert_str_eq("extended_perms", hd->module_name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	struct declaration_data *dd = current->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_t", dd->name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_DECL, current->flavor);
	dd = current->data.d_data;
	ck_assert_int_eq(DECL_TYPE, dd->flavor);
	ck_assert_str_eq("basic_dev_t", dd->name);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("~", current->data.xav_data->perms->string);
	ck_assert_str_eq("0x8927", current->data.xav_data->perms->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("35072", current->data.xav_data->perms->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("0027", current->data.xav_data->perms->string);
	ck_assert_str_eq("0028", current->data.xav_data->perms->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("0", current->data.xav_data->perms->string);
	ck_assert_str_eq("0x00", current->data.xav_data->perms->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("0x0000", current->data.xav_data->perms->string);
	ck_assert_str_eq("-", current->data.xav_data->perms->next->string);
	ck_assert_str_eq("0x00ff", current->data.xav_data->perms->next->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_ALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("1024", current->data.xav_data->perms->string);
	ck_assert_str_eq("-", current->data.xav_data->perms->next->string);
	ck_assert_str_eq("2048", current->data.xav_data->perms->next->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_DONTAUDIT, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("1024-2048", current->data.xav_data->perms->string);
	ck_assert_str_eq("35072", current->data.xav_data->perms->next->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_AUDITALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("ioctl_macro", current->data.xav_data->perms->string);
	ck_assert_ptr_nonnull(current->next);
	ck_assert_ptr_null(current->first_child);

	current = current->next;
	ck_assert_int_eq(NODE_XAV_RULE, current->flavor);
	ck_assert_int_eq(AV_RULE_NEVERALLOW, current->data.xav_data->flavor);
	ck_assert_str_eq("ioctl", current->data.xav_data->operation);
	ck_assert_str_eq("ioctl_macro", current->data.xav_data->perms->string);
	ck_assert_str_eq("0x40ff-0x41ff", current->data.xav_data->perms->next->string);
	ck_assert_ptr_null(current->next);
	ck_assert_ptr_null(current->first_child);

	ck_assert_str_eq("extended_perms", look_up_in_decl_map("basic_t", DECL_TYPE));
	ck_assert_int_eq(2, decl_map_count(DECL_TYPE));

	free_policy_node(ast);

	cleanup_parsing();

	fclose(f);

}
END_TEST

START_TEST (test_parse_ifdef) {

	set_current_module_name("ifdef_block");

	FILE *f = fopen(IFDEF_BLOCK_FILENAME, "r");
	ck_assert_ptr_nonnull(f);
	struct policy_node *ast = yyparse_wrapper(f, IFDEF_BLOCK_FILENAME, NODE_TE_FILE);
	const struct policy_node *current = ast;
	const struct policy_node *ifelse_block;

	ck_assert_ptr_nonnull(current);
	ck_assert_int_eq(NODE_TE_FILE, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_HEADER, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_IFELSE, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_null(current->next);
	ifelse_block = current;

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_M4_SIMPLE_MACRO, current->flavor);
	ck_assert_str_eq("bool1", current->data.str);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_M4_SIMPLE_MACRO, current->flavor);
	ck_assert_str_eq("true", current->data.str);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source1", current->data.av_data->sources->string);
	ck_assert_str_eq("perm1", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source1", current->data.av_data->sources->string);
	ck_assert_str_eq("perm2", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_M4_SIMPLE_MACRO, current->flavor);
	ck_assert_str_eq("bool2", current->data.str);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_M4_SIMPLE_MACRO, current->flavor);
	ck_assert_str_eq("true", current->data.str);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source2", current->data.av_data->sources->string);
	ck_assert_str_eq("perm1", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source2", current->data.av_data->sources->string);
	ck_assert_str_eq("perm2", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent->next;

	ck_assert_int_eq(NODE_M4_ARG, current->flavor);
	ck_assert_ptr_nonnull(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent);
	ck_assert_ptr_null(current->next);

	current = current->first_child;

	ck_assert_int_eq(NODE_START_BLOCK, current->flavor);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source3", current->data.av_data->sources->string);
	ck_assert_str_eq("perm1", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_nonnull(current->next);

	current = current->next;

	ck_assert_int_eq(NODE_AV_RULE, current->flavor);
	ck_assert_str_eq("source3", current->data.av_data->sources->string);
	ck_assert_str_eq("perm2", current->data.av_data->perms->string);
	ck_assert_ptr_null(current->first_child);
	ck_assert_ptr_eq(ifelse_block, current->parent->parent);
	ck_assert_ptr_null(current->next);

	current = current->parent;

	ck_assert_ptr_null(current->next);

	current = current->parent;

	ck_assert_ptr_eq(ifelse_block, current);
	ck_assert_ptr_null(current->next);

	free_policy_node(ast);
	cleanup_parsing();
	fclose(f);

}
END_TEST

static Suite *parsing_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("Parsing");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_parse_basic_te);
	tcase_add_test(tc_core, test_parse_basic_if);
	tcase_add_test(tc_core, test_parse_uncommon_constructs);
	tcase_add_test(tc_core, test_parse_interface_ifdef);
	tcase_add_test(tc_core, test_parse_blocks);
	tcase_add_test(tc_core, test_parse_empty_file);
	tcase_add_test(tc_core, test_syntax_error);
	tcase_add_test(tc_core, test_parse_bad_role_allow);
	tcase_add_test(tc_core, test_disable_booltunable_te);
	tcase_add_test(tc_core, test_disable_comment_te);
	tcase_add_test(tc_core, test_disable_comment_if);
	tcase_add_test(tc_core, test_disable_require_if);
	tcase_add_test(tc_core, test_bool_declarations);
	tcase_add_test(tc_core, test_file_flavor_mismatch);
	tcase_add_test(tc_core, test_extended_perms);
	tcase_add_test(tc_core, test_parse_ifdef);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = parsing_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
