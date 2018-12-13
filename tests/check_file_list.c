#include <check.h>
#include <stdlib.h>

#include "../src/file_list.h"
#

START_TEST (test_file_list_push_back) {

	struct policy_node *ast1 = malloc(sizeof(struct policy_node));
	struct policy_node *ast2 = malloc(sizeof(struct policy_node));
	struct policy_node *ast3 = malloc(sizeof(struct policy_node));
	struct policy_node *ast4 = malloc(sizeof(struct policy_node));

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

Suite *file_list_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("File List");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_file_list_push_back);
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
