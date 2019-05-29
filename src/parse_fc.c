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

		char *maybe_s = strtok(NULL,",");
		if ( maybe_s == NULL ) {
			goto cleanup;
		}
		char *maybe_c = strtok(NULL,",");
		int i = 0;
		while (maybe_s[i] != '\0' && maybe_s[i] != ')') {
			i++;
		}
		if (maybe_s[i] == '\0') {
			if (!maybe_c) {
				// Missing closing paren
				goto cleanup;
			}
		}
		maybe_s[i] = '\0';
		while (maybe_s[0] != '\0' && (maybe_s[0] == ' ' || maybe_s[0] == '\t')) {
			// trim beginning whitespace
			maybe_s++;
		}

		if (maybe_c) {
			while (maybe_c[i] != '\0' && maybe_c[i] != ')') {
				i++;
			}
			if (maybe_c[i] == '\0') {
				// Missing closing paren
				goto cleanup;
			}
			maybe_c[i] = '\0';
			while (maybe_c[0] != '\0' && (maybe_c[0] == ' ' || maybe_c[0] == '\t')) {
				// trim beginning whitespace
				maybe_c++;
			}
		}

		out->context = parse_context(context_part);
		if (out ->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 1;
		if (maybe_c) {
			out->context->range = malloc(strlen(maybe_s) + 1 + strlen(maybe_c) + 1);
			strcpy(out->context->range,maybe_s);
			strcat(out->context->range,":");
			strcat(out->context->range,maybe_c);
		} else {
			out->context->range = strdup(maybe_s);
		}
	} else if (strcmp("<<none>>\n", pos) == 0 || strcmp("<<none>>\r\n", pos) == 0) {
		out->context = NULL;
	} else {
		out->context = parse_context(pos);
		if (out->context == NULL) {
			goto cleanup;
		}
		out->context->has_gen_context = 0;

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
		if (len_read <= 1 || line[0] == '#') {
			continue;
		}

		// Skip over m4 constructs
		if (strncmp(line, "ifdef", 5) == 0 ||
			strncmp(line, "ifndef", 6) == 0 ||
			strncmp(line, "')", 2) == 0 ||
			strncmp(line, "', `", 4) == 0 ||
			strncmp(line, "',`", 3) == 0 ) {

			continue;
		}

		// TODO: Right now whitespace parses as an error
		// We may want to detect it and report a lower severity issue

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

