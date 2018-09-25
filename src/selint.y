%{
	#include <stdio.h>
	int yylex(void);
	void yyerror(char *);
%}

%union {
	char *string;
	char symbol;
	
}

%token <string> STRING;
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
%token OPTIONAL_POLICY;
%token GEN_REQUIRE;
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
%token POUND_SIGN;

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
	interface
	|
	optional_block
	|
	gen_require
	|
	ifdef
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

perms_list:
	string_list
	|
	TILDA string_list
	|
	STAR
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

interface:
	STRING OPEN_PAREN args CLOSE_PAREN
	;

optional_block:
	OPTIONAL_POLICY OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

gen_require:
	GEN_REQUIRE OPEN_PAREN BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

ifdef:
	IFDEF OPEN_PAREN BACKTICK STRING SINGLE_QUOTE COMMA BACKTICK lines SINGLE_QUOTE CLOSE_PAREN
	;

args:
	string_list
	|
	args COMMA string_list
	;

%%
extern int yylineno;
void yyerror(char* s) {
	fprintf(stderr, "line %d: %s\n", yylineno, s);
}
