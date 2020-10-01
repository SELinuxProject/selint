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

#include "../src/string_list.h"

START_TEST (test_str_in_sl) {

	struct string_list *sl = calloc(1, sizeof(struct string_list));

	sl->string = strdup("foo");
	sl->next = calloc(1, sizeof(struct string_list));
	sl->next->string = strdup("bar");

	ck_assert_int_eq(1, str_in_sl("foo", sl));
	ck_assert_int_eq(1, str_in_sl("bar", sl));
	ck_assert_int_eq(0, str_in_sl("baz", sl));

	ck_assert_int_eq(0, str_in_sl("foo", NULL));

	free_string_list(sl);

}
END_TEST

START_TEST (test_copy_string_list) {

	struct string_list *cur;

	struct string_list *sl1 = calloc(1, sizeof(struct string_list));

	sl1->string = strdup("foo");
	sl1->next = calloc(1, sizeof(struct string_list));
	cur = sl1->next;
	cur->string = strdup("bar");
	cur->has_incorrect_space = 1;
	cur->next = calloc(1,sizeof(struct string_list));
	cur = cur->next;
	cur->string = strdup("baz");

	struct string_list *sl2 = copy_string_list(sl1);

	ck_assert_ptr_nonnull(sl2);
	ck_assert_ptr_ne(sl1, sl2);

	ck_assert_str_eq(sl1->string, sl2->string);
	ck_assert_ptr_ne(sl1->string, sl2->string);
	ck_assert_int_eq(sl1->has_incorrect_space, sl2->has_incorrect_space);

	ck_assert_ptr_ne(sl1->next, sl2->next);
	ck_assert_ptr_nonnull(sl2->next);

	ck_assert_str_eq(sl1->next->string, sl2->next->string);
	ck_assert_ptr_ne(sl1->next->string, sl2->next->string);
	ck_assert_int_eq(sl1->next->has_incorrect_space, sl2->next->has_incorrect_space);

	ck_assert_ptr_ne(sl1->next->next, sl2->next->next);
	ck_assert_ptr_nonnull(sl2->next->next);

	ck_assert_str_eq(sl1->next->next->string, sl2->next->next->string);

	ck_assert_ptr_null(sl2->next->next->next);

	free_string_list(sl1);
	free_string_list(sl2);

}
END_TEST

START_TEST (test_copy_string_list_null) {

	ck_assert_ptr_null(copy_string_list(NULL));

}
END_TEST

START_TEST (test_sl_from_str) {

	struct string_list *sl = sl_from_str("test");
	ck_assert_ptr_nonnull(sl);
	ck_assert_str_eq("test", sl->string);
	ck_assert_int_eq(0, sl->has_incorrect_space);
	ck_assert_ptr_null(sl->next);

	free_string_list(sl);

}
END_TEST

START_TEST (test_sl_from_strn) {

	struct string_list *sl = sl_from_strn("hello world", 5);
	ck_assert_ptr_nonnull(sl);
	ck_assert_str_eq("hello", sl->string);
	ck_assert_int_eq(0, sl->has_incorrect_space);
	ck_assert_ptr_null(sl->next);

	free_string_list(sl);

	sl = sl_from_strn("hello world", 0);
	ck_assert_ptr_nonnull(sl);
	ck_assert_str_eq("", sl->string);
	ck_assert_int_eq(0, sl->has_incorrect_space);
	ck_assert_ptr_null(sl->next);

	free_string_list(sl);

}
END_TEST

START_TEST (test_sl_from_strs) {

	struct string_list *sl = sl_from_strs(2, "hello", "world");
	ck_assert_ptr_nonnull(sl);
	ck_assert_str_eq("hello", sl->string);
	ck_assert_int_eq(0, sl->has_incorrect_space);
	ck_assert_ptr_nonnull(sl->next);
	ck_assert_str_eq("world", sl->next->string);
	ck_assert_int_eq(0, sl->next->has_incorrect_space);
	ck_assert_ptr_null(sl->next->next);

	free_string_list(sl);

}
END_TEST

START_TEST (test_concat_string_lists) {

	struct string_list *res, *sl1, *sl2;

	ck_assert_ptr_null(concat_string_lists(NULL, NULL));

	sl1 = sl_from_str("hello");
	ck_assert_ptr_nonnull(sl1);

	sl2 = sl_from_str("world");
	ck_assert_ptr_nonnull(sl2);

	res = concat_string_lists(NULL, sl1);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->string);
	ck_assert_int_eq(0, res->has_incorrect_space);
	ck_assert_ptr_null(res->next);

	res = concat_string_lists(sl1, NULL);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->string);
	ck_assert_int_eq(0, res->has_incorrect_space);
	ck_assert_ptr_null(res->next);

	res = concat_string_lists(sl1, sl2);
	ck_assert_ptr_nonnull(res);
	ck_assert_str_eq("hello", res->string);
	ck_assert_int_eq(0, res->has_incorrect_space);
	ck_assert_ptr_nonnull(res->next);
	ck_assert_str_eq("world", res->next->string);
	ck_assert_int_eq(0, res->next->has_incorrect_space);
	ck_assert_ptr_null(res->next->next);

	free_string_list(res); // frees sl1 and sl2

}
END_TEST

static Suite *string_list_suite(void) {
	Suite *s;
	TCase *tc_core;

	s = suite_create("String_list");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_str_in_sl);
	tcase_add_test(tc_core, test_copy_string_list);
	tcase_add_test(tc_core, test_copy_string_list_null);
	tcase_add_test(tc_core, test_sl_from_str);
	tcase_add_test(tc_core, test_sl_from_strn);
	tcase_add_test(tc_core, test_sl_from_strs);
	tcase_add_test(tc_core, test_concat_string_lists);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void) {

	int number_failed = 0;
	Suite *s;
	SRunner *sr;

	s = string_list_suite();
	sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0)? 0 : -1;
}
