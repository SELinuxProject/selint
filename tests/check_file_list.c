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

#include "../src/file_list.h"
#

START_TEST (test_file_list_push_back) {

	struct policy_node *ast1 = malloc(sizeof(struct policy_node));
	memset(ast1, 0, sizeof(struct policy_node));
	struct policy_node *ast2 = malloc(sizeof(struct policy_node));
	memset(ast2, 0, sizeof(struct policy_node));
	struct policy_node *ast3 = malloc(sizeof(struct policy_node));
	memset(ast3, 0, sizeof(struct policy_node));
	struct policy_node *ast4 = malloc(sizeof(struct policy_node));
	memset(ast4, 0, sizeof(struct policy_node));

	struct policy_file_list *list = malloc(sizeof(struct policy_file_list));
	memset(list, 0, sizeof(struct policy_file_list));

	file_list_push_back(list, make_policy_file("file1", ast1));
	file_list_push_back(list, make_policy_file("file2", ast2));
	file_list_push_back(list, make_policy_file("file3", ast3));
	file_list_push_back(list, make_policy_file("file4", ast4));

	ck_assert_ptr_eq(list->head->file->ast, ast1);
	ck_assert_str_eq(list->head->file->filename, "file1");
	ck_assert_ptr_eq(list->head->next->file->ast, ast2);
	ck_assert_str_eq(list->head->next->file->filename, "file2");

	ck_assert_ptr_eq(list->tail->file->ast, ast4);
	ck_assert_str_eq(list->tail->file->filename, "file4");

	free_file_list(list);

}
END_TEST

START_TEST (test_make_policy_file) {
	struct policy_file *file = make_policy_file("foo", NULL);
	ck_assert_ptr_nonnull(file);
	ck_assert_str_eq(file->filename, "foo");
	ck_assert_ptr_null(file->ast);

	free(file->filename);
	free(file);
}
END_TEST

START_TEST (test_file_name_in_file_list) {
	struct policy_file_list *list = calloc(1, sizeof(struct policy_file_list));
	file_list_push_back(list, make_policy_file("foo", NULL));
	file_list_push_back(list, make_policy_file("bar", NULL));
	file_list_push_back(list, make_policy_file("baz", NULL));

	ck_assert_int_eq(0, file_name_in_file_list("not_in_list", list));
	ck_assert_int_eq(1, file_name_in_file_list("foo", list));
	ck_assert_int_eq(1, file_name_in_file_list("bar", list));
	ck_assert_int_eq(1, file_name_in_file_list("baz", list));

	free_file_list(list);
}
END_TEST

static Suite *file_list_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("File List");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_file_list_push_back);
	tcase_add_test(tc_core, test_make_policy_file);
	tcase_add_test(tc_core, test_file_name_in_file_list);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = file_list_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
