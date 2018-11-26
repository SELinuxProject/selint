%{
	#include <stdio.h>
	#include <string.h>
	#include "tree.h"
	#include "parse_functions.h"
	int yylex(void);
	void yyerror(char *);

	extern struct policy_node *ast;

	struct policy_node *cur;
%}

%union {
	char *string;
	char symbol;
	struct string_list *sl;
	enum av_rule_flavor av_flavor;
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
%token CLASS;
%token IFDEF;
%token IFNDEF;
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
%type<av_flavor> av_type
%type<sl> perms_list

%%
policy:
	header body
	;

header:
	POLICY_MODULE OPEN_PAREN STRING COMMA VERSION_NO CLOSE_PAREN { begin_parsing_te(&cur, $3); ast = cur; }
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
	type_alias
	|
	rule { printf("Here 4r\n"); }
	|
	type_transition
	|
	range_transition
	|
	interface { printf("Here 4i\n"); }
	|
	optional_block
	|
	gen_require
	|
	m4_call
	|
	COMMENT
	;

declaration:
	type_declaration
	|
	ATTRIBUTE STRING SEMICOLON
	|
	CLASS STRING perms_list SEMICOLON
	|
	role_declaration
	|
	ATTRIBUTE_ROLE STRING SEMICOLON;
	;

type_declaration:
	TYPE STRING SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2); }
	|
	TYPE STRING COMMA args SEMICOLON { insert_declaration(&cur, DECL_TYPE, $2); } // TODO: attrs
	|
	TYPE STRING ALIAS string_list SEMICOLON
	;

role_declaration:
	ROLE STRING SEMICOLON
	|
	ROLE STRING TYPES args SEMICOLON
	; 

type_alias:
	TYPEALIAS string_list ALIAS string_list SEMICOLON
	;

rule:
	av_type string_list string_list COLON string_list perms_list SEMICOLON { insert_av_rule(&cur, $1, $2, $3, $5, $6); }
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
	STRING { $$ = malloc(sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; }
	;

strings:
	strings STRING { struct string_list *cur = $1;
			while (cur->next) { cur++;}
			cur->next = malloc(sizeof(struct string_list));
			cur->next->string = strdup($2); }
	|
	STRING { $$ = malloc(sizeof(struct string_list)); $$->string = strdup($1); $$->next = NULL; }
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
	|
	TYPE_TRANSITION string_list string_list COLON string_list STRING QUOTED_STRING SEMICOLON
	;

range_transition:
	RANGE_TRANSITION string_list string_list COLON string_list mls_range SEMICOLON
	|
	RANGE_TRANSITION string_list string_list COLON string_list mls_level SEMICOLON
	;

interface:
	STRING OPEN_PAREN args CLOSE_PAREN
	|
	STRING OPEN_PAREN args CLOSE_PAREN SEMICOLON
	;

optional_block:
	OPTIONAL_POLICY OPEN_PAREN { begin_optional_policy(&cur); } 
	BACKTICK lines SINGLE_QUOTE CLOSE_PAREN { end_optional_policy(&cur); }
	;

gen_require:
	GEN_REQUIRE OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

m4_call:
	ifdef
	|
	tunable
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
	;

string_list_or_mls:
	string_list
	|
	mls_range
	|
	MLS_LEVEL
	;

mls_range:
	mls_level DASH mls_level
	;

mls_level:
	MLS_LEVEL
	|
	STRING
	;
%%
extern int yylineno;
void yyerror(char* s) {
	fprintf(stderr, "line %d: %s\n", yylineno, s);
}
