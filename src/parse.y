%{
	#include <stdio.h>
	#include <string.h>
	#include <libgen.h>
	#include "tree.h"
	#include "parse_functions.h"
	#include "check_hooks.h"
	int yylex(void);
	void yyerror(char *);

	extern struct policy_node *ast;
	extern int yylineno;
	extern char *parsing_filename;

	struct policy_node *cur;
%}

%union {
	char *string;
	char symbol;
	struct string_list *sl;
	enum av_rule_flavor av_flavor;
	enum node_flavor node_flavor;
}

%token <string> MLS_LEVEL;
%token <string> STRING;
%token <string> NUM_STRING;
%token <string> NUMBER;
%token <string> QUOTED_STRING;
%token <symbol> SYMBOL;
%token <string> VERSION_NO;

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
%token INTERFACE;
%token TEMPLATE;
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
%token AND;
%token OR;
%token XOR;
%token NOT;
%token EQUAL;
%token NOT_EQUAL;
%token COMMENT;

%left OR
%left XOR
%left AND
%right NOT
%left EQUAL NOT_EQUAL

%type<sl> string_list
%type<sl> comma_string_list
%type<sl> strings
%type<string> sl_item
%type<sl> args
%type<string> mls_range
%type<string> mls_level
%type<sl> string_list_or_mls
%type<av_flavor> av_type
%type<node_flavor> if_keyword

%%
selinux_file:
	/* empty */ { ast = calloc(1, sizeof(struct policy_node)); ast->flavor = NODE_EMPTY; }
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
	COMMENT { if (!ast) {
			cur = malloc(sizeof(struct policy_node));
			memset(cur, 0, sizeof(struct policy_node));
			cur->flavor = NODE_IF_FILE;
			ast = cur;
			set_current_module_name(parsing_filename);
		}
		insert_comment(&cur, yylineno); }
	;


header:
	POLICY_MODULE OPEN_PAREN STRING COMMA VERSION_NO CLOSE_PAREN { begin_parsing_te(&cur, $3, yylineno); if (ast) { free_policy_node(ast); } ast = cur; free($3); free($5);} // Version number isn't needed
	|
	MODULE STRING VERSION_NO SEMICOLON { begin_parsing_te(&cur, $2, yylineno); ast = cur; free($2); free($3); }
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
	SEMICOLON
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
	attribute_declaration
	|
	CLASS STRING string_list SEMICOLON { free($2); free_string_list($3); }
	|
	role_declaration
	|
	ATTRIBUTE_ROLE comma_string_list SEMICOLON { free_string_list($2); }
	|
	BOOL comma_string_list SEMICOLON { free_string_list($2); }
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

attribute_declaration:
	ATTRIBUTE STRING SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE, $2, NULL, yylineno); }
	|
	ATTRIBUTE STRING COMMA comma_string_list SEMICOLON { insert_declaration(&cur, DECL_ATTRIBUTE, $2, $4, yylineno); }
	;

role_declaration:
	ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, NULL, yylineno); free($2); }
	|
	ROLE STRING COMMA comma_string_list SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, $4, yylineno); free($2); }
	|
	ROLE STRING TYPES string_list SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, $4, yylineno); free($2); }
	; 

type_alias:
	TYPEALIAS STRING ALIAS string_list SEMICOLON { insert_type_alias(&cur, $2, yylineno); insert_aliases(&cur, $4, DECL_TYPE, yylineno); free($2); }
	;

type_attribute:
	TYPE_ATTRIBUTE STRING comma_string_list SEMICOLON { free($2); free_string_list($3); }
	;

role_attribute:
	ROLE_ATTRIBUTE STRING comma_string_list SEMICOLON { free($2); free_string_list($3); }

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
	strings sl_item { struct string_list *cur = $1; while (cur->next) { cur = cur->next; }
			cur->next = calloc(1, sizeof(struct string_list));
			cur->next->string = strdup($2);
			cur->next->next = NULL; 
			free($2); }
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
	comma_string_list COMMA STRING { struct string_list *cur = $1; while (cur->next) { cur = cur->next; }
					cur->next = calloc(1, sizeof(struct string_list));
					cur->next->string = strdup($3);
					cur->next->next = NULL;
					free($3); }
	|
	STRING { $$ = calloc(1, sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; free($1); }
	;

role_allow:
	// It is an error for this to be anything other than ALLOW, but using av_type
	// instead seems like the cleanest way to avoid ambiguities in the grammar
	av_type string_list string_list SEMICOLON { free_string_list($2); free_string_list($3); } 
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
	|
	RANGE_TRANSITION string_list string_list COLON string_list mls_level SEMICOLON {  insert_type_transition(&cur, TT_RT, $2, $3, $5, $6, NULL, yylineno); free($6); }
	;

role_transition:
	ROLE_TRANSITION string_list string_list STRING SEMICOLON { free_string_list($2); free_string_list($3); free($4); }
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
	;

require:
	gen_require_begin
	BACKTICK lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur); }
	|
	// TODO: This is bad and should be checked
	gen_require_begin
	line CLOSE_PAREN { end_gen_require(&cur); }
	|
	REQUIRE OPEN_CURLY { begin_require(&cur, yylineno); }
	lines CLOSE_CURLY { end_require(&cur); }
	;

gen_require_begin:
	GEN_REQUIRE OPEN_PAREN { begin_gen_require(&cur, yylineno); }
	;

m4_call:
	ifdef
	|
	tunable
	|
	gen_tunable
	|
	ifelse
	|
	refpolicywarn
	;

ifdef:
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA m4_args CLOSE_PAREN { free($4); }
	;

if_or_ifn:
	IFDEF
	|
	IFNDEF;

tunable:
	TUNABLE_POLICY OPEN_PAREN BACKTICK condition SINGLE_QUOTE COMMA m4_args CLOSE_PAREN
	;

gen_tunable:
	GEN_TUNABLE OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA STRING CLOSE_PAREN
	|
	GEN_TUNABLE OPEN_PAREN STRING COMMA STRING CLOSE_PAREN
	;

ifelse:
	IFELSE OPEN_PAREN m4_args CLOSE_PAREN

refpolicywarn:
	REFPOLICYWARN OPEN_PAREN BACKTICK arbitrary_m4_string SINGLE_QUOTE CLOSE_PAREN
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
	condition binary_operator condition
	|
	OPEN_PAREN condition CLOSE_PAREN
	;

binary_operator:
	AND
	|
	OR
	|
	XOR
	|
	EQUAL
	|
	NOT_EQUAL
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
	BACKTICK string_list SINGLE_QUOTE { free_string_list($2); }
	|
	STRING { free($1); }
	;

args:
	string_list_or_mls
	|
	args COMMA string_list_or_mls
	{ struct string_list *cur = $1;
	while (cur->next) { cur = cur->next; }
	cur->next = $3;
	$$ = $1; }
	|
	args STRING
	{ struct string_list *cur = $1;
	while (cur->next) { cur = cur->next; }
	cur->next = calloc(1, sizeof(struct string_list));
	cur->next->string = $2;
	cur->next->has_incorrect_space = 1;
	$$ = $1; }
	;

string_list_or_mls:
	string_list
	|
	mls_range { $$ = calloc(1, sizeof(struct string_list)); $$->next = NULL; $$->string = $1; }
	|
	MLS_LEVEL { $$ = calloc(1, sizeof(struct string_list)); $$->next = NULL; $$->string = $1; }
	;

mls_range:
	mls_level DASH mls_level { size_t len = strlen($1) + strlen($3) + 1 /* DASH */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s-%s", $1, $3);
				free($1); free($3); }
	;

mls_level:
	MLS_LEVEL { $$ = strdup($1); free($1); }
	|
	STRING { $$ = strdup($1); free($1); }
	;

cond_expr:
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	|
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	ELSE OPEN_CURLY lines CLOSE_CURLY
	;

genfscon:
	GENFSCON STRING STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN { free($2); free($3); }
	|
	GENFSCON NUM_STRING STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN { free($2); free($3); }
	;

sid:
	SID STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN { free($2); }
	;

portcon:
	PORTCON STRING port_range GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN { free($2); }
	;

port_range:
	NUM_STRING { free($1); }
	|
	NUMBER { free($1); }
	|
	NUMBER DASH NUMBER { free($1); free($3); }
	;

netifcon:
	NETIFCON STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN { free($2); }
	;

nodecon:
	NODECON two_ip_addrs GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN
	;

two_ip_addrs:
	NUM_STRING NUM_STRING { free($1); free($2); }
	|
	ipv6
	;

ipv6:
	ipv6_item
	|
	ipv6_item ipv6
	;

ipv6_item:
	STRING { free($1); }
	|
	COLON
	|
	NUMBER { free($1); }
	;

fs_use:
	FS_USE_TRANS STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON { free($2); }
	|
	FS_USE_XATTR STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON { free($2); }
	|
	FS_USE_TASK STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON { free($2); }
	;

define:
	DEFINE OPEN_PAREN m4_args CLOSE_PAREN
	;

gen_user:
	GEN_USER OPEN_PAREN args CLOSE_PAREN { free_string_list($3); }
	;

context:
	STRING COLON STRING COLON STRING { free($1); free($3); free($5); }
	|
	STRING COLON STRING COLON STRING COLON string_list_or_mls { free($1); free($3); free($5); free_string_list($7); }
	|
	STRING COLON STRING COLON STRING COLON string_list_or_mls COLON string_list_or_mls { free($1); free($3); free($5); free_string_list($7); free_string_list($9); }
	|
	STRING COLON STRING COLON STRING COMMA string_list_or_mls { free($1); free($3); free($5); free_string_list($7); }
	|
	STRING COLON STRING COLON STRING COMMA string_list_or_mls COMMA string_list_or_mls { free($1); free($3); free($5); free_string_list($7); free_string_list($9); }
	|
	// because m4
	STRING COLON STRING COLON STRING COMMA string_list_or_mls COMMA { free($1); free($3); free($5); free_string_list($7); }
	;

permissive:
	PERMISSIVE STRING SEMICOLON { free($2); }
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
		if (!ast) {
			// Must set up the AST at the beginning
			cur = malloc(sizeof(struct policy_node));
			memset(cur, 0, sizeof(struct policy_node));
			cur->flavor = NODE_IF_FILE;
			ast = cur;
			set_current_module_name(parsing_filename);
		} 
		begin_interface_def(&cur, $1, $4, yylineno); free($4); }
	;

end_interface:
	SINGLE_QUOTE CLOSE_PAREN { end_interface_def(&cur); }
	;

if_keyword:
	INTERFACE { $$ = NODE_IF_DEF; }
	|
	TEMPLATE { $$ = NODE_TEMP_DEF; }
	;

%%
extern int yylineno;
void yyerror(char* s) {
	struct check_result *res = make_check_result('F', F_ID_POLICY_SYNTAX, s);
	res->lineno = yylineno;

	struct check_data data;
	data.mod_name = get_current_module_name();
	data.filename = basename(parsing_filename);
	data.flavor = FILE_TE_FILE; // We don't know but it's unused by display_check_result
	
	display_check_result(res, &data);

	free_check_result(res);
}
