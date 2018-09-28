%{
#include <stdio.h>
#include <string.h>
#include "selint_parse.h"
int yylineno;
extern void yyerror(char *);
%}
%%
policy_module { printf("policy_module"); return POLICY_MODULE; }
type { return TYPE; }
typealias { return TYPEALIAS; }
alias { return ALIAS; }
attribute { return ATTRIBUTE; }
allow { return ALLOW; }
auditallow { return AUDIT_ALLOW; }
dontaudit { return DONT_AUDIT; }
neverallow { return NEVER_ALLOW; }
type_transition { return TYPE_TRANSITION; }
range_transition { return RANGE_TRANSITION; }
optional_policy { return OPTIONAL_POLICY; }
gen_require { return GEN_REQUIRE; }
tunable_policy { return TUNABLE_POLICY; }
class { return CLASS; }
ifdef { return IFDEF; }
s[0-9]+(:c[0-9]+)? { return MLS_LEVEL; }
[0-9]+\.[0-9]+ { printf("vno"); yylval.string = strdup(yytext); return VERSION_NO; }
[a-zA-Z][a-zA-Z0-9_]* { printf("string"); yylval.string = strdup(yytext); return STRING; };
\"[a-zA-Z][a-zA-Z0-9_]*\" { printf("quoted string"); yylval.string = strdup(yytext); return QUOTED_STRING; };
\( { printf("("); return OPEN_PAREN; }
\) { printf(")"); return CLOSE_PAREN; }
\, { printf(","); return COMMA; }
\{ { return OPEN_CURLY; }
\} { return CLOSE_CURLY; }
\: { return COLON; }
\; { return SEMICOLON; }
\` { return BACKTICK; }
\' { return SINGLE_QUOTE; }
\~ { return TILDA; }
\* { return STAR; }
\- { return DASH; }
^\#.*\n { yylineno++; return COMMENT; }
(\#.*)?\n { printf("\n"); yylineno++; }
[ \t] ; /* skip whitespace */
. { yyerror("Invalid character"); } 

%%
int yywrap(void) {
	return 1;
}
/*
int main() {
	for(int i=0; i < 20; i++) {
		yylex();
	}
	return 0;
}
*/
