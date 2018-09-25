%{
#include <stdio.h>
#include <string.h>
#include "y.tab.h"
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
optional_policy { return OPTIONAL_POLICY; }
gen_require { return GEN_REQUIRE; }
class { return CLASS; }
ifdef { return IFDEF; }
[0-9]+\.[0-9]+ { printf("vno"); yylval.string = strdup(yytext); return VERSION_NO; }
[a-zA-Z][a-zA-Z0-9_]* { printf("string"); yylval.string = strdup(yytext); return STRING; };
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
\#.*\n { yylineno++; return COMMENT; }
\n { printf("\n"); yylineno++; }
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
