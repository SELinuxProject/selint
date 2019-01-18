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
%token <string> QUOTED_STRING;
%token <symbol> SYMBOL;
%token <string> VERSION_NO;

%token POLICY_MODULE;
%token TYPE;
%token TYPEALIAS;
%token ALIAS;
%token ATTRIBUTE;
%token TYPE_ATTRIBUTE;
%token ROLE;
%token TYPES;
%token ATTRIBUTE_ROLE;
%token ALLOW;
%token AUDIT_ALLOW;
%token DONT_AUDIT;
%token NEVER_ALLOW;
%token TYPE_TRANSITION;
%token RANGE_TRANSITION;
%token OPTIONAL_POLICY;
%token GEN_REQUIRE;
%token TUNABLE_POLICY;
%token REFPOLICYWARN;
%token CLASS;
%token IFDEF;
%token IFNDEF;
%token INTERFACE;
%token TEMPLATE;
%token OPEN_PAREN;
%token COMMA;
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
%type<sl> args
%type<string> mls_range
%type<string> mls_level
%type<sl> string_list_or_mls
%type<av_flavor> av_type
%type<sl> perms_list
%type<node_flavor> if_keyword

%%
selinux_file:
	te_policy
	|
	if_file
	;

	// TE File parsing

te_policy:
	header body
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
	type_alias
	|
	rule
	|
	type_transition
	|
	range_transition
	|
	interface_call
	|
	optional_block
	|
	gen_require
	|
	m4_call
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
	CLASS STRING perms_list SEMICOLON
	|
	role_declaration
	|
	ATTRIBUTE_ROLE STRING SEMICOLON;
	;

type_declaration:
	TYPE STRING SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, yylineno); free($2); }
	|
	TYPE STRING COMMA args SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2, yylineno); free($2); free_string_list($4); } // TODO: attrs
	|
	TYPE STRING ALIAS string_list SEMICOLON
	;

attribute_declaration:
	ATTRIBUTE STRING SEMICOLON { free($2); }
	|
	ATTRIBUTE STRING COMMA args SEMICOLON { free($2); free_string_list($4); }
	;

role_declaration:
	ROLE STRING SEMICOLON
	|
	ROLE STRING TYPES args SEMICOLON
	; 

type_alias:
	TYPEALIAS string_list ALIAS string_list SEMICOLON
	;

type_attribute:
	TYPE_ATTRIBUTE STRING args SEMICOLON
	;

rule:
	av_type string_list string_list COLON string_list perms_list SEMICOLON { insert_av_rule(&cur, $1, $2, $3, $5, $6, yylineno); }
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
	STRING { $$ = malloc(sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; free($1);}
	;

strings:
	strings STRING { struct string_list *cur = $1; while (cur->next) { cur = cur->next; }
			cur->next = malloc(sizeof(struct string_list));
			cur->next->string = strdup($2);
			cur->next->next = NULL; 
			free($2); }
	|
	STRING { $$ = malloc(sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; free($1);}
	;

perms_list:
	string_list
	|
	TILDA string_list { $$ = malloc(sizeof(struct string_list));
			$$->string = strdup("~");
			$$->next = $2; }
	|
	STAR { $$ = malloc(sizeof(struct string_list)); $$->string = strdup("*"); $$->next = NULL; } 
	;

type_transition:
	TYPE_TRANSITION string_list string_list COLON string_list STRING SEMICOLON
	{ insert_type_transition(&cur, $2, $3, $5, $6, NULL, yylineno); }
	|
	TYPE_TRANSITION string_list string_list COLON string_list STRING QUOTED_STRING SEMICOLON
	{ insert_type_transition(&cur, $2, $3, $5, $6, $7, yylineno); }
	;

range_transition:
	RANGE_TRANSITION string_list string_list COLON string_list mls_range SEMICOLON
	|
	RANGE_TRANSITION string_list string_list COLON string_list mls_level SEMICOLON
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

refpolicywarn:
	REFPOLICYWARN OPEN_PAREN BACKTICK arbitrary_m4_string SINGLE_QUOTE CLOSE_PAREN
	;

arbitrary_m4_string:
	STRING
	|
	STRING arbitrary_m4_string
	|
	OPEN_PAREN arbitrary_m4_string
	|
	CLOSE_PAREN arbitrary_m4_string
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
	BACKTICK lines SINGLE_QUOTE
	|
	m4_args COMMA BACKTICK lines SINGLE_QUOTE
	;

args:
	string_list_or_mls
	|
	args COMMA string_list_or_mls
	{ struct string_list *cur = $1; while (cur->next) { cur = cur->next; }
	cur->next = $3; }
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

	// IF File parsing
if_file:
	if_lines
	;

if_lines:
	if_lines if_line
	|
	if_line { if (!cur) {
		// Must set up the AST at the beginning
		cur = malloc(sizeof(struct policy_node));
		memset(cur, 0, sizeof(struct policy_node));
		cur->flavor = NODE_IF_FILE;
		ast = cur; }
	}
	;

if_line:
	interface_def
	|
	COMMENT
	;

interface_def:
	if_keyword OPEN_PAREN BACKTICK STRING SINGLE_QUOTE { begin_interface_def(&cur, $1, $4, yylineno); free($4); }
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
