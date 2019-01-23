%{
	#include <stdio.h>
	#include <string.h>
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
%token <string> NUMBER;
%token <string> QUOTED_STRING;
%token <symbol> SYMBOL;
%token <string> VERSION_NO;

%token POLICY_MODULE;
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
%token FS_USE_TRANS;
%token FS_USE_XATTR;
%token FS_USE_TASK;
%token DEFINE;
%token GEN_CONTEXT;
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
	te_policy
	|
	comments te_policy
	|
	if_file
	|
	comments if_file
	|
	comments {if (!ast) {
			// This is an if file with no interfaces
			cur = malloc(sizeof(struct policy_node));
			memset(cur, 0, sizeof(struct policy_node));
			cur->flavor = NODE_IF_FILE;
			ast = cur;
		} }
	;

	// TE File parsing

te_policy:
	header body
	;

comments:
	COMMENT
	|
	comments COMMENT
	;

header:
	POLICY_MODULE OPEN_PAREN STRING COMMA VERSION_NO CLOSE_PAREN { begin_parsing_te(&cur, $3, yylineno); ast = cur; free($3); free($5);} // Version number isn't needed
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
	gen_require
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
	fs_use
	|
	define
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
	CLASS STRING string_list SEMICOLON
	|
	role_declaration
	|
	ATTRIBUTE_ROLE args SEMICOLON
	|
	BOOL args SEMICOLON
	;

type_declaration:
	TYPE STRING SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, yylineno); free($2); }
	|
	TYPE STRING COMMA args SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, yylineno); free($2); free_string_list($4); } // TODO: attrs
	|
	TYPE STRING ALIAS args SEMICOLON
	;

attribute_declaration:
	ATTRIBUTE STRING SEMICOLON { free($2); }
	|
	ATTRIBUTE STRING COMMA args SEMICOLON { free($2); free_string_list($4); }
	;

role_declaration:
	ROLE STRING SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, yylineno); free($2); }
	|
	ROLE STRING TYPES args SEMICOLON { insert_declaration(&cur, DECL_ROLE, $2, yylineno); free($2); free_string_list($4); }
	; 

type_alias:
	TYPEALIAS string_list ALIAS string_list SEMICOLON
	;

type_attribute:
	TYPE_ATTRIBUTE STRING args SEMICOLON
	;

role_attribute:
	ROLE_ATTRIBUTE STRING args SEMICOLON

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
	TILDA string_list { $$ = malloc(sizeof(struct string_list));
			$$->string = strdup("~");
			$$->next = $2; }
	|
	sl_item { $$ = malloc(sizeof(struct string_list)); $$->string = $1; $$->next = NULL; }
	|
	STAR { $$ = malloc(sizeof(struct string_list)); $$->string = strdup("*"); $$->next = NULL; }
	;

strings:
	strings sl_item { struct string_list *cur = $1; while (cur->next) { cur = cur->next; }
			cur->next = malloc(sizeof(struct string_list));
			cur->next->string = strdup($2);
			cur->next->next = NULL; 
			free($2); }
	|
	sl_item { $$ = malloc(sizeof(struct string_list)); $$->string = $1; $$->next = NULL; } 
	;

sl_item:
	STRING { $$ = strdup($1); free($1);}
	|
	DASH STRING { $$ = malloc(sizeof(char) * (strlen($2) + 2));
			$$[0] = '-';
			strcat($$, $2);
			free($2);}
	|
	QUOTED_STRING { $$ = strdup($1); free($1);}
	;

role_allow:
	// It is an error for this to be anything other than ALLOW, but using av_type
	// instead seems like the cleanest way to avoid ambiguities in the grammar
	av_type string_list string_list SEMICOLON 
	;

type_transition:
	TYPE_TRANSITION string_list string_list COLON string_list STRING SEMICOLON
	{ insert_type_transition(&cur, $2, $3, $5, $6, NULL, yylineno); }
	|
	TYPE_TRANSITION string_list string_list COLON string_list STRING QUOTED_STRING SEMICOLON
	{ insert_type_transition(&cur, $2, $3, $5, $6, $7, yylineno); }
	|
	TYPE_MEMBER string_list string_list COLON string_list STRING SEMICOLON
	|
	TYPE_CHANGE string_list string_list COLON string_list STRING SEMICOLON
	;

range_transition:
	RANGE_TRANSITION string_list string_list COLON string_list mls_range SEMICOLON
	|
	RANGE_TRANSITION string_list string_list COLON string_list mls_level SEMICOLON
	;

role_transition:
	ROLE_TRANSITION string_list string_list STRING SEMICOLON
	;

interface_call:
	STRING OPEN_PAREN args CLOSE_PAREN
	{ insert_interface_call(&cur, $1, $3, yylineno); free($1); }
	|
	STRING OPEN_PAREN args CLOSE_PAREN SEMICOLON
	{ insert_interface_call(&cur, $1, $3, yylineno); free($1); }
	;

optional_block:
	OPTIONAL_POLICY OPEN_PAREN { begin_optional_policy(&cur, yylineno); } 
	BACKTICK lines SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	;

gen_require:
	GEN_REQUIRE OPEN_PAREN BACKTICK { begin_gen_require(&cur, yylineno); }
	lines SINGLE_QUOTE CLOSE_PAREN { end_gen_require(&cur); }
	;

m4_call:
	ifdef
	|
	tunable
	|
	ifelse
	|
	refpolicywarn
	;

ifdef:
	if_or_ifn OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA m4_args CLOSE_PAREN
	;

if_or_ifn:
	IFDEF
	|
	IFNDEF;

tunable:
	TUNABLE_POLICY OPEN_PAREN BACKTICK condition SINGLE_QUOTE COMMA m4_args CLOSE_PAREN
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
	STRING
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
	STRING
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
	BACKTICK string_list SINGLE_QUOTE
	;

args:
	string_list_or_mls
	|
	args COMMA string_list_or_mls
	{ struct string_list *cur = $1;
	while (cur->next) { cur = cur->next; }
	cur->next = $3;
	$$= $1; }
	;

string_list_or_mls:
	string_list
	|
	mls_range { $$ = malloc(sizeof(struct string_list)); $$->next = NULL; $$->string = $1; }
	|
	MLS_LEVEL { $$ = malloc(sizeof(struct string_list)); $$->next = NULL; $$->string = $1; }
	;

mls_range:
	mls_level DASH mls_level { size_t len = strlen($1) + strlen($3) + 1 /* DASH */ + 1 /* NT */;
				$$ = malloc(len);
				snprintf($$, len, "%s-%s", $1, $3); }
	;

mls_level:
	MLS_LEVEL
	|
	STRING
	;

cond_expr:
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	|
	IF OPEN_PAREN condition CLOSE_PAREN OPEN_CURLY lines CLOSE_CURLY
	ELSE OPEN_CURLY lines CLOSE_CURLY
	;

genfscon:
	GENFSCON STRING STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN
	;

sid:
	SID STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN
	;

portcon:
	PORTCON STRING port_range GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN
	;

port_range:
	NUMBER
	|
	NUMBER DASH NUMBER
	;

netifcon:
	NETIFCON STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN
	;

fs_use:
	FS_USE_TRANS STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON
	|
	FS_USE_XATTR STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON
	|
	FS_USE_TASK STRING GEN_CONTEXT OPEN_PAREN context CLOSE_PAREN SEMICOLON
	;

define:
	DEFINE OPEN_PAREN m4_args CLOSE_PAREN

context:
	STRING COLON STRING COLON STRING
	|
	STRING COLON STRING COLON STRING COLON string_list_or_mls
	|
	STRING COLON STRING COLON STRING COLON string_list_or_mls COLON string_list_or_mls
	|
	STRING COLON STRING COLON STRING COMMA string_list_or_mls
	;

	// IF File parsing
if_file:
	interface_def if_lines
	|
	interface_def
	;

if_lines:
	if_lines if_line
	|
	if_line
	;

if_line:
	interface_def
	|
	COMMENT
	;

interface_def:
	if_keyword OPEN_PAREN BACKTICK STRING SINGLE_QUOTE {
		if (!ast) {
			// Must set up the AST at the beginning
			cur = malloc(sizeof(struct policy_node));
			memset(cur, 0, sizeof(struct policy_node));
			cur->flavor = NODE_IF_FILE;
			ast = cur;
		} 
		begin_interface_def(&cur, $1, $4, yylineno); free($4); }
	COMMA BACKTICK lines SINGLE_QUOTE CLOSE_PAREN { end_interface_def(&cur); }
	;

if_keyword:
	INTERFACE { $$ = NODE_IF_DEF; }
	|
	TEMPLATE { $$ = NODE_TEMP_DEF; }
	;

%%
extern int yylineno;
void yyerror(char* s) {
	struct check_result *res = malloc(sizeof(struct check_result));
	res->lineno = yylineno;
	res->severity = 'F';
	res->check_id = F_ID_POLICY_SYNTAX;
	res->message = strdup(s);

	struct check_data data;
	data.mod_name = get_current_module_name();
	data.filename = parsing_filename;
	data.flavor = FILE_TE_FILE; // We don't know but it's unused by display_check_result
	
	display_check_result(res, &data);

	free(data.mod_name);
	free_check_result(res);
}
