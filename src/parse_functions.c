#include <stdlib.h>
#include <string.h>

#include "parse_functions.h"
#include "selint_error.h"
#include "tree.h"
#include "template.h"

char *module_name = NULL;
char *parsing_filename = NULL;

enum selint_error begin_parsing_te(struct policy_node **cur, char *mn,
				   unsigned int lineno)
{

	set_current_module_name(mn);

	*cur = malloc(sizeof(struct policy_node));
	if (!*cur) {
		return SELINT_OUT_OF_MEM;
	}

	memset(*cur, 0, sizeof(struct policy_node));

	(*cur)->flavor = NODE_TE_FILE;
	(*cur)->data.str = strdup(mn);
	(*cur)->lineno = lineno;

	return SELINT_SUCCESS;
}

void set_current_module_name(char *mn)
{
	if (module_name != NULL) {
		free(module_name);
	}
	module_name = strdup(mn);
}

char *get_current_module_name()
{
	return module_name;
}

int is_in_require(struct policy_node *cur)
{
	while (cur->parent) {
		cur = cur->parent;
		if (cur->flavor == NODE_GEN_REQ || cur->flavor == NODE_REQUIRE) {
			return 1;
		}
	}
	return 0;
}

enum selint_error insert_comment(struct policy_node **cur, unsigned int lineno)
{
	union node_data data;
	data.str = NULL;
	enum selint_error ret =
	    insert_policy_node_next(*cur, NODE_COMMENT, data, lineno);
	if (ret != SELINT_SUCCESS) {
		return ret;
	}
	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_declaration(struct policy_node **cur,
				     enum decl_flavor flavor, char *name,
				     struct string_list *attrs,
				     unsigned int lineno)
{

	if (!is_in_require(*cur)) {
		// In a require block, the objects arent being declared
		// Otherwise, we need to insert them into the appropriate map

		char *temp_name = get_name_if_in_template(*cur);

		if (temp_name) {
			// We are inside a template, so we need to save declarations in the template map
			// TODO: What about nested templates?  This case may require some thought
			insert_decl_into_template_map(temp_name, flavor, name);
		} else if ('$' != name[0]) {
			// If the name starts with $ we're probably doing something like associating
			// a role with types in interfaces

			char *mn = get_current_module_name();

			if (!mn) {
				return SELINT_NO_MOD_NAME;
			}

			insert_into_decl_map(name, mn, flavor);

		}
	}

	struct declaration_data *data =
	    (struct declaration_data *)malloc(sizeof(struct declaration_data));
	if (!data) {
		return SELINT_OUT_OF_MEM;
	}

	memset(data, 0, sizeof(struct declaration_data));

	data->flavor = flavor;
	data->name = strdup(name);
	data->attrs = attrs;

	union node_data nd;
	nd.d_data = data;

	enum selint_error ret =
	    insert_policy_node_next(*cur, NODE_DECL, nd, lineno);

	if (ret != SELINT_SUCCESS) {
		free(data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_aliases(struct policy_node **cur,
				 struct string_list *aliases,
				 enum decl_flavor flavor, unsigned int lineno)
{

	struct string_list *alias = aliases;

	while (alias) {
		char *temp_name = get_name_if_in_template(*cur);
		if (temp_name) {
			insert_decl_into_template_map(temp_name, flavor,
						      alias->string);
		} else {
			char *mn = get_current_module_name();
			if (!mn) {
				free_string_list(aliases);
				return SELINT_NO_MOD_NAME;
			}

			insert_into_decl_map(alias->string, mn, flavor);
		}
		union node_data nd;
		nd.str = strdup(alias->string);
		enum selint_error ret = insert_policy_node_child(*cur,
		                                                 NODE_ALIAS,
		                                                 nd,
		                                                 lineno);
		if (ret != SELINT_SUCCESS) {
			return ret;
		}
		alias = alias->next;
	}

	free_string_list(aliases);

	return SELINT_SUCCESS;
}

enum selint_error insert_type_alias(struct policy_node **cur, char *type,
				    unsigned int lineno)
{

	union node_data nd;
	nd.str = strdup(type);
	enum selint_error ret = insert_policy_node_next(*cur,
	                                                NODE_TYPE_ALIAS,
	                                                nd,
	                                                lineno);
	if (ret != SELINT_SUCCESS) {
		return ret;
	}

	*cur = (*cur)->next;
	return SELINT_SUCCESS;
}

enum selint_error insert_av_rule(struct policy_node **cur,
				 enum av_rule_flavor flavor,
				 struct string_list *sources,
				 struct string_list *targets,
				 struct string_list *object_classes,
				 struct string_list *perms, unsigned int lineno)
{

	struct av_rule_data *av_data = malloc(sizeof(struct av_rule_data));

	av_data->flavor = flavor;
	av_data->sources = sources;
	av_data->targets = targets;
	av_data->object_classes = object_classes;
	av_data->perms = perms;

	union node_data nd;
	nd.av_data = av_data;

	enum selint_error ret = insert_policy_node_next(*cur,
	                                                NODE_AV_RULE,
	                                                nd,
	                                                lineno);
	if (ret != SELINT_SUCCESS) {
		free_av_rule_data(av_data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_role_allow(struct policy_node **cur, char *from_role,
				    char *to_role, unsigned int lineno)
{
	struct role_allow_data *ra_data =
	    malloc(sizeof(struct role_allow_data));

	ra_data->from = strdup(from_role);
	ra_data->to = strdup(to_role);

	union node_data nd;
	nd.ra_data = ra_data;

	enum selint_error ret =
	    insert_policy_node_next(*cur, NODE_ROLE_ALLOW, nd, lineno);
	if (ret != SELINT_SUCCESS) {
		free_ra_data(ra_data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_type_transition(struct policy_node **cur,
					 enum tt_flavor flavor,
					 struct string_list *sources,
					 struct string_list *targets,
					 struct string_list *object_classes,
					 char *default_type, char *name,
					 unsigned int lineno)
{

	struct type_transition_data *tt_data =
	    malloc(sizeof(struct type_transition_data));

	tt_data->sources = sources;
	tt_data->targets = targets;
	tt_data->object_classes = object_classes;
	tt_data->default_type = strdup(default_type);
	if (name) {
		tt_data->name = strdup(name);
	} else {
		tt_data->name = NULL;
	}
	tt_data->flavor = flavor;

	union node_data nd;
	nd.tt_data = tt_data;

	enum selint_error ret = insert_policy_node_next(*cur,
	                                                NODE_TT_RULE,
	                                                nd,
	                                                lineno);
	if (ret != SELINT_SUCCESS) {
		free_type_transition_data(tt_data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_interface_call(struct policy_node **cur, char *if_name,
					struct string_list *args,
					unsigned int lineno)
{
	struct if_call_data *if_data = malloc(sizeof(struct if_call_data));
	if_data->name = strdup(if_name);
	if_data->args = args;

	char *template_name = get_name_if_in_template(*cur);

	if (template_name) {
		insert_call_into_template_map(template_name, if_data);
	} else {
		add_template_declarations(if_name, args, NULL, module_name);
	}

	union node_data nd;
	nd.ic_data = if_data;
	enum selint_error ret = insert_policy_node_next(*cur,
	                                                NODE_IF_CALL,
	                                                nd,
	                                                lineno);
	if (ret != SELINT_SUCCESS) {
		free_if_call_data(if_data);
		return ret;
	}

	*cur = (*cur)->next;

	return SELINT_SUCCESS;
}

enum selint_error insert_permissive_statement(struct policy_node **cur,
					      char *domain, unsigned int lineno)
{
	union node_data nd;
	nd.str = strdup(domain);
	enum selint_error ret = insert_policy_node_next(*cur,
	                                                NODE_PERMISSIVE,
	                                                nd,
	                                                lineno);
	if (ret != SELINT_SUCCESS) {
		return ret;
	}

	*cur = (*cur)->next;
	return SELINT_SUCCESS;
}

enum selint_error begin_block(struct policy_node **cur,
			      enum node_flavor block_type, char *data,
			      unsigned int lineno)
{
	union node_data nd;
	nd.str = data;
	enum selint_error ret = insert_policy_node_next(*cur,
	                                                block_type,
	                                                nd,
	                                                lineno);

	if (ret != SELINT_SUCCESS) {
		return ret;
	}

	*cur = (*cur)->next;

	nd.str = NULL;
	ret = insert_policy_node_child(*cur, NODE_START_BLOCK, nd, lineno);
	if (ret != SELINT_SUCCESS) {
		*cur = (*cur)->prev;
		free_policy_node((*cur)->next);
		return ret;
	}

	*cur = (*cur)->first_child;

	return SELINT_SUCCESS;
}

enum selint_error end_block(struct policy_node **cur,
			    enum node_flavor block_type)
{

	if ((*cur)->parent == NULL || (*cur)->parent->flavor != block_type) {
		return SELINT_NOT_IN_BLOCK;
	}

	*cur = (*cur)->parent;
	return SELINT_SUCCESS;
}

enum selint_error begin_optional_policy(struct policy_node **cur,
					unsigned int lineno)
{

	return begin_block(cur, NODE_OPTIONAL_POLICY, (char *)NULL, lineno);
}

enum selint_error end_optional_policy(struct policy_node **cur)
{

	return end_block(cur, NODE_OPTIONAL_POLICY);
}

enum selint_error begin_optional_else(struct policy_node **cur,
				      unsigned int lineno)
{
	return begin_block(cur, NODE_OPTIONAL_ELSE, (char *)NULL, lineno);
}

enum selint_error end_optional_else(struct policy_node **cur)
{
	return end_block(cur, NODE_OPTIONAL_ELSE);
}

enum selint_error begin_interface_def(struct policy_node **cur,
				      enum node_flavor flavor, char *name,
				      unsigned int lineno)
{

	switch (flavor) {
	case NODE_IF_DEF:
	case NODE_TEMP_DEF:
		break;
	default:
		return SELINT_BAD_ARG;
	}

	insert_into_ifs_map(name, get_current_module_name());

	return begin_block(cur, flavor, strdup(name), lineno);
}

enum selint_error end_interface_def(struct policy_node **cur)
{

	return end_block(cur, NODE_IF_DEF);
}

enum selint_error begin_gen_require(struct policy_node **cur,
				    unsigned int lineno)
{

	return begin_block(cur, NODE_GEN_REQ, (char *)NULL, lineno);
}

enum selint_error end_gen_require(struct policy_node **cur)
{

	return end_block(cur, NODE_GEN_REQ);
}

enum selint_error begin_require(struct policy_node **cur, unsigned int lineno)
{

	return begin_block(cur, NODE_REQUIRE, (char *)NULL, lineno);
}

enum selint_error end_require(struct policy_node **cur)
{

	return end_block(cur, NODE_REQUIRE);
}

void cleanup_parsing()
{
	if (module_name) {
		free(module_name);
		module_name = NULL;
	}

	free_all_maps();
}
