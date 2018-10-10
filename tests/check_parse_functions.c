#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "../src/parse_functions.h"

#define EXAMPLE_TYPE_1 "foo_t"
#define EXAMPLE_TYPE_2 "bar_t"
#define EXAMPLE_TYPE_3 "baz_t"

START_TEST (test_begin_parsing_te) {

	struct policy_node *cur;

	ck_assert_int_eq(SELINT_SUCCESS, begin_parsing_te(cur, "example"));

	ck_assert_ptr_nonnull(cur);
	ck_assert_ptr_null(cur->parent);
	ck_assert_ptr_null(cur->next);
	ck_assert_ptr_null(cur->prev);
	ck_assert_ptr_null(cur->first_child);
	ck_assert_int_eq(NODE_TE_FILE, cur->flavor);
	ck_assert_str_eq(cur->data.string, "example");

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(cur));

}
END_TEST

int main(void) {
	return 0;
}
