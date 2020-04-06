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
%{
	#include <stdio.h>
	#include <string.h>
	#include <libgen.h>
	#include "tree.h"
	#include "parse_functions.h"
	#include "check_hooks.h"
	int yylex(void);
	void yyerror(const char *);

	extern struct policy_node *ast;
	extern unsigned int yylineno;
	extern char *parsing_filename;

	struct policy_node *cur;
	#define YYDEBUG 1
%}

%union {
	char *string;
	char symbol;
	struct string_list *sl;
	enum av_rule_flavor av_flavor;
	enum node_flavor node_flavor;
}

%token <string> STRING;
%token <string> NUM_STRING;
%token <string> IPV4;
%token <string> IPV6;
%token <string> NUMBER;
%token <string> QUOTED_STRING;
%token <string> VERSION_NO;
%token <string> SELINT_COMMAND;

%destructor { free($$); } STRING
%destructor { free($$); } NUM_STRING
%destructor { free($$); } IPV4
%destructor { free($$); } IPV6
%destructor { free($$); } NUMBER
%destructor { free($$); } QUOTED_STRING
%destructor { free($$); } VERSION_NO

%token POLICY_MODULE;
%token MODULE;
%token TYPE;
%token TYPEALIAS;
%token ALIAS;
%token ATTRIBUTE;
%token BOOL;
%token TYPE_ATTRIBUTE;
%token ROLE_ATTRIBUTE;
%token ROLE;
%token TYPES;
%token ATTRIBUTE_ROLE;
%token ALLOW;
%token AUDIT_ALLOW;
%token DONT_AUDIT;
%token NEVER_ALLOW;
%token TYPE_TRANSITION;
%token TYPE_MEMBER;
%token TYPE_CHANGE;
%token RANGE_TRANSITION;
%token ROLE_TRANSITION;
%token OPTIONAL_POLICY;
%token GEN_REQUIRE;
%token GEN_BOOL;
%token GEN_TUNABLE;
%token REQUIRE;
%token TUNABLE_POLICY;
%token IFELSE;
%token REFPOLICYWARN;
%token CLASS;
%token IFDEF;
%token IFNDEF;
%token IF;
%token ELSE;
%token GENFSCON;
%token SID;
%token PORTCON;
%token NETIFCON;
%token NODECON;
%token FS_USE_TRANS;
%token FS_USE_XATTR;
%token FS_USE_TASK;
%token DEFINE;
%token GEN_USER;
%token GEN_CONTEXT;
%token PERMISSIVE;
%token TYPEBOUNDS;
%token INTERFACE;
%token TEMPLATE;
%token USERDEBUG_OR_ENG;
%token FILE_TYPE_SPECIFIER;
%token OPEN_PAREN;
%token COMMA;
%token PERIOD;
%token CLOSE_PAREN;
%token OPEN_CURLY;
%token CLOSE_CURLY;
%token COLON;
%token SEMICOLON;
%token BACKTICK;
%token SINGLE_QUOTE;
%token TILDA;
%token STAR;
%token DASH;
%left AND;
%left OR;
%left XOR;
%right NOT;
%left EQUAL;
%left NOT_EQUAL;
%token COMMENT;

%type<sl> string_list
%type<sl> comma_string_list
%type<sl> strings
%type<string> sl_item
%type<sl> arg
%type<sl> args
%type<string> mls_range
%type<string> mls_level
%type<string> mls_component
%type<av_flavor> av_type
%type<node_flavor> if_keyword

%destructor { free($$); } mls_component mls_level mls_range sl_item
%destructor { free_string_list($$); } arg args comma_string_list string_list strings

%%
selinux_file:
	%empty
	/* empty */ { ast->flavor = NODE_EMPTY; }
	|
	te_policy
	|
	comments te_policy
	|
	if_file
	|
	comments if_file
	|
	comments
	;

	// TE File parsing

te_policy:
	header body
	;

comments:
	comment
	|
	comment comments
	;

comment:
	COMMENT	{ if (!cur) { cur = ast; }
	          insert_comment(&cur, yylineno); }
	;


header:
	POLICY_MODULE OPEN_PAREN STRING COMMA header_version CLOSE_PAREN { if(!cur) { cur = ast; } insert_header(&cur, $3, HEADER_MACRO, yylineno); free($3); } // Version number isn't needed
	|
	MODULE STRING header_version SEMICOLON { cur = ast; insert_header(&cur, $2, HEADER_BARE, yylineno); free($2); }
	;

header_version:
	VERSION_NO { free($1); }
	|
	NUMBER { free($1); }
	;

body:
	lines
	;

lines:
	lines line
	|
	line
	;

line:
	bare_line
	|
	bare_line SELINT_COMMAND { save_command(cur, $2); free($2); }
	;

bare_line:
	declaration
	|
	type_attribute
	|
	role_attribute
	|
	type_alias
	|
	rule
	|
	role_allow
	|
	role_types
	|
	type_transition
	|
	range_transition
	|
	role_transition
	|
	interface_call
	|
	optional_block
	|
	require
	|
	m4_call
	|
	cond_expr
	|
	genfscon
	|
	sid
	|
	portcon
	|
	netifcon
	|
	nodecon
	|
	fs_use
	|
	define
	|
	gen_user
	|
	permissive
	|
	typebounds
	|
	SEMICOLON { insert_semicolon(&cur, yylineno); }
	|
	COMMENT
	// Would like to do error recovery, but the best strategy seems to be to skip
	// to next newline, which lex doesn't give us right now.
	// Also, we would need to know in yyerror whether the error was recoverable
	//|
	//error { yyerrok; yyclearin;}
	;

declaration:
	type_declaration
	|
	ATTRIBUTE STRING SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE, $2, NULL, yylineno); free($2); }
	|
	CLASS STRING string_list SEMICOLON { insert_declaration(&cur, DECL_CLASS, $2, $3, yylineno); free($2); }
	|
	ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, NULL, yylineno); free($2); }
	|
	ATTRIBUTE_ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE_ROLE, $2, NULL, yylineno); free($2); }
	|
	bool_declaration
	;

type_declaration:
	TYPE STRING SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, NULL, yylineno); free($2); }
	|
	TYPE STRING COMMA comma_string_list SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, $4, yylineno); free($2); }
	|
	TYPE STRING ALIAS string_list SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, NULL, yylineno); free($2); insert_aliases(&cur, $4, DECL_TYPE, yylineno); }
	|
	TYPE STRING ALIAS STRING COMMA comma_string_list SEMICOLON {
				insert_declaration(&cur, DECL_TYPE, $2, NULL, yylineno);
				free($2);
				struct string_list *tmp = calloc(1, sizeof(struct string_list));
				tmp->string = $4;
				tmp->next = $6;
				insert_aliases(&cur, tmp, DECL_TYPE, yylineno); }
	;

bool_declaration:
	BOOL STRING SEMICOLON { insert_declaration(&cur, DECL_BOOL, $2, NULL, yylineno); free($2); }
	|
	GEN_BOOL OPEN_PAREN STRING COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $3, NULL, yylineno); free($3); free($5); }
	|
	GEN_TUNABLE OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $4, NULL, yylineno); free($4); free($7); }
	|
	GEN_TUNABLE OPEN_PAREN STRING COMMA STRING CLOSE_PAREN { insert_declaration(&cur, DECL_BOOL, $3, NULL, yylineno); free($3); free($5); }
	;

type_alias:
	TYPEALIAS STRING ALIAS string_list SEMICOLON { insert_type_alias(&cur, $2, yylineno); insert_aliases(&cur, $4, DECL_TYPE, yylineno); free($2); }
	;

type_attribute:
	TYPE_ATTRIBUTE STRING comma_string_list SEMICOLON { insert_type_attribute(&cur, $2, $3, yylineno); free($2); }
	;

role_attribute:
	ROLE_ATTRIBUTE STRING comma_string_list SEMICOLON { insert_role_attribute(&cur, $2, $3, yylineno); free($2); }

rule:
	av_type string_list string_list COLON string_list string_list SEMICOLON { insert_av_rule(&cur, $1, $2, $3, $5, $6, yylineno); }
	;

av_type:
	ALLOW { $$ = AV_RULE_ALLOW; }
	|
	AUDIT_ALLOW { $$ = AV_RULE_AUDITALLOW; }
	|
	DONT_AUDIT { $$ = AV_RULE_DONTAUDIT; }
	|
	NEVER_ALLOW { $$ = AV_RULE_NEVERALLOW; }
	;

string_list:
	OPEN_CURLY strings CLOSE_CURLY { $$ = $2; }
	|
	TILDA string_list { $$ = calloc(1, sizeof(struct string_list));
			$$->string = strdup("~");
			$$->next = $2; }
	|
	sl_item { $$ = calloc(1, sizeof(struct string_list)); $$->string = $1; $$->next = NULL; }
	|
	STAR { $$ = calloc(1, sizeof(struct string_list)); $$->string = strdup("*"); $$->next = NULL; }
	;

strings:
	strings sl_item { struct string_list *current = $1; while (current->next) { current = current->next; }
			current->next = calloc(1, sizeof(struct string_list));
			current->next->string = strdup($2);
			current->next->next = NULL;
			free($2);
			$$ = $1; }
	|
	sl_item { $$ = calloc(1, sizeof(struct string_list)); $$->string = $1; $$->next = NULL; }
	;

sl_item:
	STRING { $$ = strdup($1); free($1);}
	|
	DASH STRING { $$ = malloc(sizeof(char) * (strlen($2) + 2));
			$$[0] = '-';
			$$[1] = '\0';
			strcat($$, $2);
			free($2);}
	|
	QUOTED_STRING { $$ = strdup($1); free($1);}
	;

comma_string_list:
	comma_string_list COMMA STRING { struct string_list *current = $1; while (current->next) { current = current->next; }
					current->next = calloc(1, sizeof(struct string_list));
					current->next->string = strdup($3);
					current->next->next = NULL;
					free($3);
					$$ = $1; }
	|
	STRING { $$ = calloc(1, sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; free($1); }
	;

role_allow:
	// It is an error for this to be anything other than "ALLOW STRING STRING", but it
	// is impossible for the parser to parse such a grammar since it doesn't know until
	// getting to the semicolon whether to classify the tokens specifically or generically.
	// So, we can just parse generically and then check for the failure case
	av_type string_list string_list SEMICOLON { if ($1 != AV_RULE_ALLOW
                                                        || $2->next != NULL
                                                        || $3->next != NULL) {
								free_string_list($2);
								free_string_list($3);
								YYERROR; }
	                                            insert_role_allow(&cur, $2->string, $3->string, yylineno);
	                                            free_string_list($2);
	                                            free_string_list($3);}
	;

role_types:
        ROLE STRING TYPES string_list SEMICOLON { insert_role_types(&cur, $2, $4, yylineno); free($2); }
        ;

type_transition:
	TYPE_TRANSITION string_list string_list COLON string_list STRING SEMICOLON
	{ insert_type_transition(&cur, TT_TT, $2, $3, $5, $6, NULL, yylineno); free($6); }
	|
	TYPE_TRANSITION string_list string_list COLON string_list STRING QUOTED_STRING SEMICOLON
	{ insert_type_transition(&cur, TT_TT, $2, $3, $5, $6, $7, yylineno); free($6); free($7); }
	|
	TYPE_MEMBER string_list string_list COLON string_list STRING SEMICOLON { insert_type_transition(&cur, TT_TM, $2, $3, $5, $6, NULL, yylineno); free($6); }
	|
	TYPE_CHANGE string_list string_list COLON string_list STRING SEMICOLON { insert_type_transition(&cur, TT_TC, $2, $3, $5, $6, NULL, yylineno); free($6); }
	;

range_transition:
	RANGE_TRANSITION string_list string_list COLON string_list mls_range SEMICOLON { insert_type_transition(&cur, TT_RT, $2, $3, $5, $6, NULL, yylineno); free($6); }
	;

role_transition:
	ROLE_TRANSITION string_list string_list STRING SEMICOLON { insert_role_transition(&cur, $2, $3, $4, yylineno); free($4); }
	;

interface_call:
	STRING OPEN_PAREN args CLOSE_PAREN
	{ insert_interface_call(&cur, $1, $3, yylineno); free($1); }
	|
	STRING OPEN_PAREN CLOSE_PAREN
	{ insert_interface_call(&cur, $1, NULL, yylineno); free($1); }
	;

optional_block:
	optional_open
	lines SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	|
	optional_open
	SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	|
	optional_open
	lines SINGLE_QUOTE COMMA { end_optional_policy(&cur); }
	BACKTICK { begin_optional_else(&cur, yylineno); }
	lines SINGLE_QUOTE CLOSE_PAREN { end_optional_else(&cur); }
	;

optional_open:
	OPTIONAL_POLICY OPEN_PAREN BACKTICK { begin_optional_policy(&cur, yylineno); }
	|
	OPTIONAL_POLICY OPEN_PAREN BACKTICK SELINT_COMMAND { begin_optional_policy(&cur, yylineno); save_command(cur->parent, $4); free($4); }
	;

require:
	gen_require_begin
	BACKTICK require_lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur, 0); }
	|
	gen_require_begin
	BACKTICK SELINT_COMMAND require_lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur, 0); save_command(cur, $3); free($3); }
	|
	gen_require_begin
	require_lines CLOSE_PAREN { end_gen_require(&cur, 1); }
	|
	REQUIRE OPEN_CURLY { begin_require(&cur, yylineno); }
	require_lines CLOSE_CURLY { end_require(&cur); }
	|
	REQUIRE OPEN_CURLY SELINT_COMMAND { begin_require(&cur, yylineno); save_command(cur->parent, $3); }
	require_lines CLOSE_CURLY { end_require(&cur); free($3); }
	;

gen_require_begin:
	GEN_REQUIRE OPEN_PAREN { begin_gen_require(&cur, yylineno); }
	|
	GEN_REQUIRE OPEN_PAREN SELINT_COMMAND { begin_gen_require(&cur, yylineno); save_command(cur->parent, $3); free($3); }
	;

require_lines:
	require_lines require_line
	|
	require_line
	;

require_line:
	require_bare
	|
	require_bare SELINT_COMMAND { save_command(cur, $2); free($2); }
	;

require_bare:
	TYPE comma_string_list SEMICOLON {
		const struct string_list *iter = $2;
		for (iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_TYPE, iter->string, NULL, yylineno);
		free_string_list($2);
		}
	|
	ATTRIBUTE comma_string_list SEMICOLON {
		const struct string_list *iter = $2;
		for (iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ATTRIBUTE, iter->string, NULL, yylineno);
		free_string_list($2);
		}
	|
	ROLE comma_string_list SEMICOLON {
		const struct string_list *iter = $2;
		for (iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ROLE, iter->string, NULL, yylineno);
		free_string_list($2);
		}
	|
	ATTRIBUTE_ROLE comma_string_list SEMICOLON {
		const struct string_list *iter = $2;
		for (iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_ATTRIBUTE_ROLE, iter->string, NULL, yylineno);
		free_string_list($2);
		}
	|
	BOOL comma_string_list SEMICOLON {
		const struct string_list *iter = $2;
		for (iter = $2; iter; iter = iter->next) insert_declaration(&cur, DECL_BOOL, iter->string, NULL, yylineno);
		free_string_list($2);
		}
	|
	CLASS STRING string_list SEMICOLON { insert_declaration(&cur, DECL_CLASS, $2, $3, yylineno); free($2); }
	|
	COMMENT
	;

m4_call:
	ifdef
	|
	tunable
	|
	ifelse
	|
	refpolicywarn
	|
	userdebug_or_eng
	;

ifdef:
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA { begin_ifdef(&cur, yylineno); }
	m4_args CLOSE_PAREN { end_ifdef(&cur); free($4); }
	;

if_or_ifn:
	IFDEF
	|
	IFNDEF;

tunable:
	TUNABLE_POLICY OPEN_PAREN BACKTICK { begin_tunable_policy(&cur, yylineno); }
	condition SINGLE_QUOTE COMMA m4_args CLOSE_PAREN { end_tunable_policy(&cur); }
	|
	TUNABLE_POLICY OPEN_PAREN { begin_tunable_policy(&cur, yylineno); }
	condition COMMA m4_args CLOSE_PAREN { end_tunable_policy(&cur); }
	;

ifelse:
	IFELSE OPEN_PAREN m4_args CLOSE_PAREN

refpolicywarn:
	REFPOLICYWARN OPEN_PAREN BACKTICK arbitrary_m4_string SINGLE_QUOTE CLOSE_PAREN
	;

userdebug_or_eng:
	USERDEBUG_OR_ENG OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

arbitrary_m4_string:
	m4_string_elem
	|
	m4_string_elem arbitrary_m4_string
	|
	BACKTICK m4_string_elem SINGLE_QUOTE
	;

m4_string_elem:
	STRING { free($1); }
	|
	OPEN_PAREN
	|
	CLOSE_PAREN
	|
	COMMA
	|
	PERIOD
	|
	COLON
	;

condition:
	STRING { free($1); }
	|
	NOT condition
	|
	condition AND condition
	|
	condition OR condition
	|
	condition XOR condition
	|
	condition EQUAL condition
	|
	condition NOT_EQUAL condition
	|
	OPEN_PAREN condition CLOSE_PAREN
	;

m4_args:
	m4_argument
	|
	m4_args COMMA m4_argument
	;

m4_argument:
	BACKTICK SINGLE_QUOTE
	|
	BACKTICK lines SINGLE_QUOTE
	|
	BACKTICK strings SINGLE_QUOTE { free_string_list($2); }
	|
	STRING { free($1); }
	;

arg:
	string_list
	|
	BACKTICK strings SINGLE_QUOTE { $$ = $2; }
	|
	BACKTICK SINGLE_QUOTE { char *empty = malloc(1);
				empty[0] = '\0';
				$$ = malloc(sizeof(struct string_list));
				$$->string = empty;
				$$->next = NULL; }
	;

args:
	arg
	|
	args COMMA arg
	{ struct string_list *current = $1;
	while (current->next) { current = current->next; }
	current->next = $3;
	$$ = $1; }
	|
	args sl_item
	{ struct string_list *current = $1;
	while (current->next) { current = current->next; }
	current->next = calloc(1, sizeof(struct string_list));
	current->next->string = $2;
	current->next->has_incorrect_space = 1;
	$$ = $1; }
	;

mls_range:
	mls_level DASH mls_level { size_t len = strlen($1) + strlen($3) + 1 /* DASH */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s-%s", $1, $3);
				free($1); free($3); }
	|
	mls_level
	;

mls_level:
	mls_component
	|
	mls_component COLON mls_component { size_t len = strlen($1) + strlen($3) + 1 /* COLON */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s:%s", $1, $3);
				free($1); free($3); }
	;

mls_component:
	STRING { $$ = strdup($1); free($1); }
	|
	STRING PERIOD STRING { size_t len = strlen($1) + strlen($3) + 1 /* PERIOD */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s.%s", $1, $3);
				free($1); free($3); }
	;

cond_expr:
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	|
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	ELSE OPEN_CURLY lines CLOSE_CURLY
	;

genfscon:
	GENFSCON STRING STRING genfscon_context { free($2); free($3); }
	|
	GENFSCON NUM_STRING STRING genfscon_context { free($2); free($3); }
	;

genfscon_context:
	context
	|
	FILE_TYPE_SPECIFIER context
	;

sid:
	SID STRING context { free($2); }
	;

portcon:
	PORTCON STRING port_range context { free($2); }
	;

port_range:
	NUM_STRING { free($1); }
	|
	NUMBER { free($1); }
	|
	// TODO: This only happens with whitespace around the dash.  NUM_STRING catches "1000-1001" type
	// names.  Is that actually a valid scenario?
	NUMBER DASH NUMBER { free($1); free($3); }
	;

netifcon:
	NETIFCON STRING context context { free($2); }
	;

nodecon:
	NODECON two_ip_addrs context
	;

two_ip_addrs:
	IPV4 IPV4 { free($1); free($2); }
	|
	IPV6 IPV6 { free($1); free($2); }
	;

fs_use:
	FS_USE_TRANS STRING context SEMICOLON { free($2); }
	|
	FS_USE_XATTR STRING context SEMICOLON { free($2); }
	|
	FS_USE_TASK STRING context SEMICOLON { free($2); }
	;

define:
	DEFINE OPEN_PAREN m4_args CLOSE_PAREN
	;

gen_user:
	GEN_USER OPEN_PAREN args CLOSE_PAREN { free_string_list($3); }
	;

context:
	raw_context
	|
	GEN_CONTEXT OPEN_PAREN raw_context CLOSE_PAREN
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range CLOSE_PAREN { free($5); }
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range COMMA mls_range CLOSE_PAREN { free($5); free($7); }
	|
	GEN_CONTEXT OPEN_PAREN raw_context COMMA mls_range COMMA CLOSE_PAREN { free($5); }
	;

raw_context:
	STRING COLON STRING COLON STRING { free($1); free($3); free($5); }
	|
	STRING COLON STRING COLON STRING COLON mls_range { free($1); free($3); free($5); free($7); }
	;

permissive:
	PERMISSIVE STRING SEMICOLON { insert_permissive_statement(&cur, $2, yylineno); free($2);}
	;

typebounds:
	TYPEBOUNDS STRING STRING SEMICOLON { free($2); free($3); }
	;

	// IF File parsing
if_file:
	interface_def if_lines
	|
	interface_def
	//|
	// Empty file
	//EOF
	;

if_lines:
	if_lines if_line
	|
	if_line
	;

if_line:
	interface_def
	|
	COMMENT { insert_comment(&cur, yylineno); }
	;

interface_def:
	start_interface lines end_interface
	|
	start_interface end_interface
	;

start_interface:
	if_keyword OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK {
		if (!cur) {
			cur = ast;
		}
		begin_interface_def(&cur, $1, $4, yylineno); free($4); }
	;

end_interface:
	SINGLE_QUOTE CLOSE_PAREN { end_interface_def(&cur); }
	;

if_keyword:
	INTERFACE { $$ = NODE_INTERFACE_DEF; }
	|
	TEMPLATE { $$ = NODE_TEMP_DEF; }
	;

%%
void yyerror(const char* s) {
	struct check_result *res = make_check_result('F', F_ID_POLICY_SYNTAX, s);
	res->lineno = yylineno;

	struct check_data data;
	data.mod_name = get_current_module_name();
	char *copy = strdup(parsing_filename);
	data.filename = basename(copy);
	data.flavor = FILE_TE_FILE; // We don't know but it's unused by display_check_result

	display_check_result(res, &data);

	free(copy);
	free_check_result(res);
}
