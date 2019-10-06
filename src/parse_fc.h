#ifndef PARSE_FC_H
#define PARSE_FC_H

#include "tree.h"

// Takes in a null terminated string that is an fc entry and populates an fc_entry struct
struct fc_entry *parse_fc_line(char *line);

struct sel_context *parse_context(char *context_str);

// Parse an fc file and return a pointer to an abstract syntax tree representing the file
struct policy_node *parse_fc_file(char *filename);
#endif
