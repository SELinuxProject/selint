#ifndef PARSE_FC_H
#define PARSE_FC_H

struct sel_context {
	int has_gen_context; // 1 if context is wrapped in gen_context, 0 if not
	char *user;
	char *role;
	char *type;
	char *range;
};

struct fc_entry {
	char *path;
	char obj;
	struct sel_context *context;
};

// Takes in a null terminated string that is an fc entry and populates an fc_entry struct
struct fc_entry * parse_fc_line(char *line);

struct sel_context * parse_context(char *context_str);

// Parse an fc file and return a pointer to an abstract syntax tree representing the file
struct policy_node *parse_fc_file(char *filename);

void free_fc_entry(struct fc_entry *to_free);

void free_sel_context(struct sel_context *to_free);

#endif
