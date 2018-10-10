#include <check.h>
#include <string.h>
#include <stdlib.h>

#include "../src/tree.h"

#define EXAMPLE_TYPE_1 "foo_t"
#define EXAMPLE_TYPE_2 "bar_t"
#define EXAMPLE_TYPE_3 "baz_t"

struct av_rule * make_example_av_rule() {

	// allow foo_t { bar_t baz_t }:file { read write getattr };
	struct av_rule *av_rule_data = malloc(sizeof(struct av_rule));

	av_rule_data->flavor = AV_RULE_ALLOW;

	av_rule_data->sources = malloc(sizeof(char*) + 1);
	ck_assert_ptr_nonnull(av_rule_data->sources);

	av_rule_data->sources[0] = strdup(EXAMPLE_TYPE_1);
	ck_assert_ptr_nonnull(*av_rule_data->sources);

	av_rule_data->sources[1] = NULL;

	av_rule_data->targets = malloc(sizeof(char*) * 2 + 1);
	ck_assert_ptr_nonnull(av_rule_data->sources);

	av_rule_data->targets[0] = strdup(EXAMPLE_TYPE_2);
	ck_assert_ptr_nonnull(av_rule_data->sources[0]);

	av_rule_data->targets[1] = strdup(EXAMPLE_TYPE_3);
	ck_assert_ptr_nonnull(av_rule_data->sources[1]);

	av_rule_data->targets[2] = NULL;

	av_rule_data->object_classes = malloc(sizeof(char*));
	ck_assert_ptr_nonnull(av_rule_data->object_classes);

	av_rule_data->object_classes[0] = strdup("file");
	ck_assert_ptr_nonnull(av_rule_data->object_classes[0]);

	av_rule_data->object_classes[1] = NULL;

	av_rule_data->perms = malloc(sizeof(char*) * 4);
	ck_assert_ptr_nonnull(av_rule_data->perms);

	av_rule_data->perms[0] = strdup("read");
	ck_assert_ptr_nonnull(av_rule_data->perms[0]);

	av_rule_data->perms[1] = strdup("write");
	ck_assert_ptr_nonnull(av_rule_data->perms[1]);

	av_rule_data->perms[2] = strdup("getattr");
	ck_assert_ptr_nonnull(av_rule_data->perms[2]);

	return av_rule_data;

}

START_TEST (test_insert_policy_node_av_rule) {

	struct policy_node parent_node;
	parent_node.parent = NULL;
	parent_node.next = NULL;
	parent_node.prev = NULL;
	parent_node.first_child = NULL;
	parent_node.flavor = NODE_TE_FILE;
	parent_node.data.av = NULL;

	union node_data av_data;
	av_data.av = make_example_av_rule();

	ck_assert_int_eq(SELINT_SUCCESS, insert_policy_node(&parent_node, NODE_AV_RULE, av_data));

	ck_assert_ptr_nonnull(parent_node.first_child);
	ck_assert_ptr_eq(parent_node.first_child->data.av, av_data.av);
	ck_assert_int_eq(parent_node.first_child->flavor, NODE_AV_RULE);

	ck_assert_int_eq(SELINT_SUCCESS, free_policy_node(parent_node.first_child));

}
END_TEST

int main(void) {
	return 0;
}
