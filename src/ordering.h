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

#ifndef ORDERING_H
#define ORDERING_H
#include <stddef.h>

#include "selint_error.h"
#include "tree.h"
#include "check_hooks.h"

enum order_difference_reason {
	ORDER_EQUAL  =0,
	ORDER_SECTION=1,
	ORDER_DECLARATION_SUBSECTION,
	ORDER_LOCAL_SUBSECTION,
	ORDER_ALPHABETICAL,
	ORDERING_ERROR=-1024, // Since we will be negating values of this enum
	                      // we want it to have a signed internal
	                      // representation.  The compiler gets to choose which
	                      // so by having a negative value explicitly declared
	                      // we force it to be signed
};

enum local_subsection {
	LSS_SELF,
	LSS_OWN,
	LSS_RELATED,
	LSS_KERNEL_MOD,
	LSS_KERNEL,
	LSS_SYSTEM,
	LSS_OTHER,
	LSS_BUILD_OPTION,
	LSS_BOOLEAN,
	LSS_TUNABLE,
	LSS_OPTIONAL,
	LSS_UNKNOWN,
};

struct section_data {
	char *section_name; // The name of the section this section_data
	                    // node contains rules for.  This can be either
	                    // the name of a type, or a special name beginning
	                    // with _.  Special names are "_declarations" for
	                    // the declarations section at the top and
	                    // "_non_ordered" for nodes that should be ignored
	                    // in ordering
	unsigned int lineno_count;
	unsigned int lines_sum;
	float avg_line;
	struct section_data *next;
};

struct order_node {
	const struct policy_node *node;
	int seq_prev;            // The index of previous node in the sequence
	                         // or -1 if this is the first node in the sequence
	int end_of_seq;          // This is the index of the smallest value
	                         // of an end of a sequence of length i+1, where
	                         // i is the index of this node in the array
	unsigned int in_order;
};

struct ordering_metadata {
	const char *mod_name;
	struct section_data *sections;
	size_t order_node_len;
	struct order_node nodes[];
};

/**********************************
* Allocate and initialize an ordering_metadata for the structure.
* Calculate the sections and order them.
* This function allocates memory for, but does not populate the
* nodes[] array.  That will be populated on the next pass in the
* calculate_longest_increasing_subsequence function.
* data (in) - The metadata about the file being scanned
* head (in) - Pointer to the file node at the top of the AST
* for a file.
*
* Returns - A new ordering_metadata structure with all memory allocated
* and all data except the nodesp[ array populated.  The caller is
* responsible for freeing all memory.  Returns NULL on error
**********************************/
struct ordering_metadata *prepare_ordering_metadata(const struct check_data *data, const struct policy_node *head);

/**********************************
* Calculate the longest increasing subsequence in a given file
* Misordered nodes are nodes that are not in this sequence.
* Updates the ordering_metadata structure to mark the in order and
* out of order nodes in the nodes[] array.
* head (in) - Pointer to the file node at the top of the AST
* for a file.
* ordering (in/out) - A structure of metadata that has been generated
* by a call to prepare_ordering_metadata for use in the ordering
* comp_func (in) - A function to call for comparison of nodes.  It should
* return a positive value if the second node should go after the first,
* a negative value is the second node should go before the first, and 0
* if the two nodes can go in any relative order.
**********************************/
void calculate_longest_increasing_subsequence(const struct policy_node *head,
                                              struct ordering_metadata *ordering,
                                              enum order_difference_reason (*comp_func)(const struct ordering_metadata *order_data,
                                                                                        const struct policy_node *first,
                                                                                        const struct policy_node *second));

/**********************************
* Add information about a line on lineno in section section_name
* to the list of sections
**********************************/
enum selint_error add_section_info(struct section_data *sections,
                                   const char *section_name,
                                   unsigned int lineno);

/**********************************
* Get the section name for a particular policy node.  This is typically
* the source type for most node varieties. For the declarations section
* at the top it is "_declaration"
**********************************/
const char *get_section(const struct policy_node *node);

/**********************************
* Run through all sections in the section_data linked list and set
* the average line number variable for each based on the sum and
* count of line numbers
**********************************/
void calculate_average_lines(struct section_data *sections);

/**********************************
* Get the average line number of a section, based on the section name
**********************************/
float get_avg_line_by_name(const char *section_name, const struct section_data *sections);

/**********************************
* Get the subsection within the rules for a domain for a particular policy node
**********************************/
enum local_subsection get_local_subsection(const char *mod_name,
                                           const struct policy_node *node,
                                           enum order_conf variant);

/**********************************
* Compare two nodes according to the refpolicy ordering conventions
* located at https://github.com/SELinuxProject/refpolicy/wiki/StyleGuide
* Variant is the config option for how strictly to enforce the style guide.
* ORDER_REF - enforce the style guide as written
* ORDER_LIGHT - enforce the style guide with the following exceptions:
*     - No distinction between kernel and system layer,
*       just kernel module -> non-optional -> optional
* ORDER_LAX - enforce the style guide with the following exceptions:
*     - No ordering restrictions are enforced on the relative ordering
*     of interface calls and blocks
* Return a positive value if the second node should go after the first,
* a negative value is the second node should go before the first and
* zero if they can go in either order.
**********************************/
enum order_difference_reason compare_nodes_refpolicy_generic(const struct ordering_metadata *ordering_data,
                                                             const struct policy_node *first,
                                                             const struct policy_node *second,
                                                             enum order_conf variant);

/**********************************
* Wrapper for compare_nodes_refpolicy_generic for refpolicy ordering
**********************************/
enum order_difference_reason compare_nodes_refpolicy(const struct ordering_metadata *ordering_data,
                                                     const struct policy_node *first,
                                                     const struct policy_node *second);

/**********************************
* Wrapper for compare_nodes_refpolicy_generic for refpolicy-light ordering
**********************************/
enum order_difference_reason compare_nodes_refpolicy_light(const struct ordering_metadata *ordering_data,
                                                           const struct policy_node *first,
                                                           const struct policy_node *second);

/**********************************
* Wrapper for compare_nodes_refpolicy_generic for refpolicy-lax ordering
**********************************/
enum order_difference_reason compare_nodes_refpolicy_lax(const struct ordering_metadata *ordering_data,
                                                         const struct policy_node *first,
                                                         const struct policy_node *second);


/**********************************
* Get a string describing the local subsection.
* The strings for kernel and system will be inserted
* into a description by get_ordering_reason, so if they
* are modified, that code should be modified as well.
**********************************/
const char *lss_to_string(enum local_subsection lss);

/**********************************
* Get a string explaining why a node is out of order.
* This is done by looking for the nearest node that is globally
* in order and relatively out of order with this node and checking
* what the reason for their out of order comparison is
**********************************/
char *get_ordering_reason(struct ordering_metadata *order_data, unsigned int index, enum order_conf variant);

void free_ordering_metadata(struct ordering_metadata *to_free);

void free_section_data(struct section_data *to_free);

#endif
