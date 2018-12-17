#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "parse_fc.h"
#include "tree.h"

// "gen_context("
#define GEN_CONTEXT_LEN 12

struct fc_entry * parse_fc_line(char *line) {
	char whitespace[] = " \t";

	struct fc_entry *out = malloc(sizeof(struct fc_entry));
	memset(out, 0, sizeof(struct fc_entry));

	char *orig_line = strdup(line); // If the object class is ommitted, we need to revert

	char *pos = strtok(line, whitespace);

	out->path = strdup(pos);

	pos = strtok(NULL, whitespace);

	if (pos == NULL) {
		goto cleanup;
	}

	if (pos[0] == '-') {
		if ( pos[2] != '\0') {
			goto cleanup;
		}
		out->obj = pos[1];
		pos = strtok(NULL, whitespace);
		if (pos == NULL ) {
			goto cleanup;
		}
	}

	// pos points to the start of the context, but spaces in the context may have been
	// overwitten by strtok
	strcpy(line, orig_line);

	if (strncmp("gen_context(", pos, GEN_CONTEXT_LEN) == 0) {
		pos += GEN_CONTEXT_LEN; // Next character
		char *context_part = strtok(pos, ",");
		if (context_part == NULL) {
			goto cleanup;
		}

		char *tmp = strtok(NULL,",");
		if ( tmp == NULL ) {
			goto cleanup;
		}
		int i = 0;
		while (tmp[i] != '\0' && tmp[i] != ')') {
			i++;
		}
		if (tmp[i] == '\0') {
			// Missing closing paren
			goto cleanup;
		}
		tmp[i] = '\0';
		while (tmp[0] != '\0' && (tmp[0] == ' ' || tmp[0] == '\t')) {
			// trim beginning whitespace
			tmp++;
		}

		out->context = parse_context(context_part);
		if (out ->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 1;
		out->context->range = strdup(tmp);
	} else {
		out->context = parse_context(pos);
		if (out->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 0;
	} 

	if (out->context == NULL) {
		goto cleanup;
	}

	free(orig_line);
	return out;

cleanup:
	free(orig_line);
	free_fc_entry(out);
	return NULL;
}

struct sel_context * parse_context(char *context_str) {

	if (strchr(context_str, '(')) {
		return NULL;
	}

	struct sel_context *context = malloc(sizeof(struct sel_context));
	memset(context, 0, sizeof(struct sel_context));
	// User
	char *pos = strtok(context_str, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->user = strdup(pos);

	// Role
	pos = strtok(NULL, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->role = strdup(pos);

	// Type
	pos = strtok(NULL, ":");

	if (pos == NULL) {
		goto cleanup;
	}

	context->type = strdup(pos);

	pos = strtok(NULL, ":");

	if (pos) {
		context->range = strdup(pos);
		if(strtok(NULL, ":")) {
			goto cleanup;
		}
	}

	return context;

cleanup:
	free_sel_context(context);
	return NULL;
}

struct policy_node * parse_fc_file(char *filename) {
	FILE *fd = fopen(filename, "r");
	if (!fd) {
		return NULL;
	}

	struct policy_node *head = malloc(sizeof(struct policy_node));
	memset(head, 0, sizeof(struct policy_node));
	head->flavor = NODE_FC_FILE;

	struct policy_node *cur = head;

	char *line = NULL;

	size_t len_read = 0;
	size_t buf_len = 0;
	int lineno = 0;
	while ((len_read = getline(&line, &buf_len, fd)) != -1) {
		lineno++;
		if (len_read <= 1) {
			continue;
		}
		struct fc_entry *entry = parse_fc_line(line);
		enum node_flavor flavor;
		if (entry == NULL) {
			flavor = NODE_ERROR;
		} else {
			flavor = NODE_FC_ENTRY;
		}
		if ( insert_policy_node_next(cur, flavor, entry, lineno) != SELINT_SUCCESS ) {
			free_policy_node(head);
			fclose(fd);
			return NULL;
		}
		cur = cur->next;
		free(line);
		line = NULL;
		buf_len = 0;
	}
	free(line); // getline alloc must be freed even if getline failed
	fclose(fd);
			
	return head;
}

