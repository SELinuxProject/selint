#ifndef PARSING_FUNCTIONS_H
#define PARSING_FUNCTIONS_H

#include "selint_error.h"
#include "tree.h"
#include "maps.h"

/**********************************
* begin_parsing_te
* Called at the beginning of parsing a te file to set up AST for a te file
* cur (in, out) - Will be allocated to point to the first node of the tree
* module_name (in) - The name of the policy module
*
* Returns - SELINT error code
**********************************/
enum selint_error begin_parsing_te(struct policy_node **cur, char *module_name,
                                   unsigned int lineno);

/**********************************
* Set the name of the current module to mn
**********************************/
void set_current_module_name(char *mn);

/**********************************
* Return the name of the current module
**********************************/
char *get_current_module_name();

/**********************************
* insert_comment
* Add a comment node at the next node in the tree, allocating all memory for it.
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated declaration node
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_comment(struct policy_node **cur, unsigned int lineno);

/**********************************
* insert_declaration
* Add a declaration node at the next node in the tree, allocating all memory for it
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated declaration node
* flavor (in)- What sort of declaration this is
* name (in) - The name of the item being declared
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_declaration(struct policy_node **cur,
                                     enum decl_flavor flavor, char *name,
                                     struct string_list *attrs,
                                     unsigned int lineno);

/**********************************
* insert_aliases
* Add alias nodes below the declaration and insert the aliases into the type map
* cur (in) - The current spot in the tree.  Will not be changed
* aliases (in) - The aliases.  This function will free the list
* flavor (in) - The flavor being declared
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_aliases(struct policy_node **cur,
                                 struct string_list *aliases,
                                 enum decl_flavor flavor, unsigned int lineno);

/**********************************
* insert_type_alias
* Add a typealias rule node at the next node in the tree, allocating all memory for it
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated av rule node
* type (in) - The name of the type in the node.
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/

enum selint_error insert_type_alias(struct policy_node **cur, char *type,
                                    unsigned int lineno);

/**********************************
* insert_av_rule
* Add an av rule node at the next node in the tree, allocating all memory for it
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated av rule node
* flavor (in) - What sort of av rule this is
* sources (in) - (memory allocated by caller) the sources in the rule
* targets (in) - (memory allocated by caller) the targets in the rule
* object_classes (in) - (memory allocated by caller) the object classes in the rule
* perms (in) - (memory allocated by caller) the perms in the rule
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_av_rule(struct policy_node **cur,
                                 enum av_rule_flavor flavor,
                                 struct string_list *sources,
                                 struct string_list *targets,
                                 struct string_list *object_classes,
                                 struct string_list *perms,
                                 unsigned int lineno);

/**********************************
* insert_role_allow
* Add a role allow node at the next node in the tree, allocating all memory for it
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated av rule node
* from_role (in) - The role allowed to transition from
* to_role (in) - The role allowed to transition to
* lineno (in) - The line number of the rule
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_role_allow(struct policy_node **cur, char *from_role,
                                    char *to_role, unsigned int lineno);

/**********************************
* insert_type_transition
* Add a type transition node at the next node in the tree, allocating all memory for it
* cur (in, out) - The current spot in the tree.  Will be updated to point to
*	the newly allocated av rule node
* flavor (in) - The variety of type transition role.  The normal case is type_transition (TT_TT),
* but other options include type_member (TT_TM), type_change (TT_TC) and range_transition (TT_RT)
* sources (in) - (memory allocated by caller) The sources in the rule
* targets (in) - (memory allocated by caller) the targets in the rule
* object_classes (in) - (memory allocated by caller) the object classes in the rule
* default_type (in) - The type to transition to
* name (in) - The name of the file for named transitions.  Can be NULL if not specified.
* lineno (in) - The line number of the rule
*
* Returns - SELINT error code
**********************************/
enum selint_error insert_type_transition(struct policy_node **cur,
                                         enum tt_flavor flavor,
                                         struct string_list *sources,
                                         struct string_list *targets,
                                         struct string_list *object_classes,
                                         char *default_type, char *name,
                                         unsigned int lineno);

enum selint_error insert_interface_call(struct policy_node **cur, char *name,
                                        struct string_list *args,
                                        unsigned int lineno);

enum selint_error insert_permissive_statement(struct policy_node **cur,
                                              char *domain,
                                              unsigned int lineno);

/**********************************
* begin_optional_policy
* Add an optional policy node at the next node in the tree.  Create its first child
* as the start of the block.  Set cur to the child node. Allocate all memory for
* both nodes.
* cur (in, out) - The current spot in the tree.  Will be updated to point to the
* first child of the optional_policy node
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error begin_optional_policy(struct policy_node **cur,
                                        unsigned int lineno);

/**********************************
* end_optional_policy
* Complete the optional policy block by moving cur back up to the parent level
* cur (in, out) - The current spot in the tree.  Will be updated to point to the
* parent optional policy node
*
* Returns - SELINT error code
**********************************/
enum selint_error end_optional_policy(struct policy_node **cur);

/**********************************
* begin_optional_else
* Add the else portion of an optional policy node at the next node in the tree.  Create its first child
* as the start of the block.  Set cur to the child node. Allocate all memory for
* both nodes.
* cur (in, out) - The current spot in the tree.  Will be updated to point to the
* first child of the optional_policy node
* lineno (in) - The line number
*
* Returns - SELINT error code
**********************************/
enum selint_error begin_optional_else(struct policy_node **cur,
                                      unsigned int lineno);

/**********************************
* end_optional_policy
* Complete the optional policy else block by moving cur back up to the parent level
* cur (in, out) - The current spot in the tree.  Will be updated to point to the
* parent optional policy node
*
* Returns - SELINT error code
**********************************/
enum selint_error end_optional_else(struct policy_node **cur);

enum selint_error begin_interface_def(struct policy_node **cur,
                                      enum node_flavor flavor, char *name,
                                      unsigned int lineno);

enum selint_error end_interface_def(struct policy_node **cur);

enum selint_error begin_gen_require(struct policy_node **cur,
                                    unsigned int lineno);

enum selint_error end_gen_require(struct policy_node **cur);

enum selint_error begin_require(struct policy_node **cur, unsigned int lineno);

enum selint_error end_require(struct policy_node **cur);

/**********************************
* save_command
* Save an selint control command in the tree.  These go at the end of lines
* and modify selint behavior while checking that line.
* Current commands are:
* - selint-disable:[check-id]
* cur (in) - The current spot in the tree.  Will be modified with information
* about the command
* comm (in) - What command string was in the comment
*
* Returns - SELint error code
**********************************/
enum selint_error save_command(struct policy_node *cur, char *comm);

/**********************************
* insert_type_attribute
* Insert a type_attribute node into the tree
* cur (in, out) - The current spot in the tree.  Will be updated to point to the
* new node.
* type (in) - The type specified in the statement
* attrs (in) - The attributes specified in the statement
* lineno (in) - The line number
*
* Returns - SELint error code
**********************************/
enum selint_error insert_type_attribute(struct policy_node **cur, char *type, struct string_list *attrs, unsigned int lineno);

/**********************************
* cleanup_parsing
* Call after all parsing is done to free up memory
**********************************/
void cleanup_parsing();

#endif
