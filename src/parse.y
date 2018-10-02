%{
	#include <stdio.h>
	int yylex(void);
	void yyerror(char *);
%}

%union {
	char *string;
	char symbol;
	
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
%token COMMENT;

%%
policy:
	header body
	;

header:
	POLICY_MODULE OPEN_PAREN STRING COMMA VERSION_NO CLOSE_PAREN { printf("yacc: %s %s", $3, $5); }
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
	rule
	|
	type_transition
	|
	range_transition
	|
	interface
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
	TYPE args SEMICOLON
	|
	ATTRIBUTE STRING SEMICOLON
	|
	CLASS STRING perms_list SEMICOLON
	;

type_alias:
	TYPEALIAS string_list ALIAS string_list SEMICOLON;

rule:
	av_type string_list string_list COLON string_list perms_list SEMICOLON
	;

av_type:
	ALLOW
	|
	AUDIT_ALLOW
	|
	DONT_AUDIT
	|
	NEVER_ALLOW
	;

string_list:
	OPEN_CURLY strings CLOSE_CURLY
	|
	STRING
	;

strings:
	strings STRING
	|
	STRING
	;

perms_list:
	string_list
	|
	TILDA string_list
	|
	STAR
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
	;

optional_block:
	OPTIONAL_POLICY OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

gen_require:
	GEN_REQUIRE OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

m4_call:
	macro_name OPEN_PAREN m4_body CLOSE_PAREN
	;

macro_name:
	IFDEF
	|
	TUNABLE_POLICY
	;

m4_body:
	BACKTICK STRING SINGLE_QUOTE COMMA m4_args
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
	mls_level
	;

mls_range:
	mls_level DASH mls_level
	;

mls_level:
	STRING
	|
	MLS_LEVEL
	;
%%
extern int yylineno;
void yyerror(char* s) {
	fprintf(stderr, "line %d: %s\n", yylineno, s);
}
