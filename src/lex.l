%{
#include <stdio.h>
#include <string.h>
#include "tree.h"
#include "parse.h"
int yylineno;
extern void yyerror(char *);
%}
%option nounput
%option noinput
%%
policy_module { return POLICY_MODULE; }
module { return MODULE; }
type { return TYPE; }
typealias { return TYPEALIAS; }
alias { return ALIAS; }
attribute { return ATTRIBUTE; }
bool { return BOOL; }
typeattribute { return TYPE_ATTRIBUTE; }
roleattribute { return ROLE_ATTRIBUTE; }
role { return ROLE; }
types {  return TYPES; }
attribute_role { return ATTRIBUTE_ROLE; }
allow { return ALLOW; }
auditallow { return AUDIT_ALLOW; }
dontaudit { return DONT_AUDIT; }
neverallow { return NEVER_ALLOW; }
type_transition { return TYPE_TRANSITION; }
type_member { return TYPE_MEMBER; }
type_change { return TYPE_CHANGE; }
range_transition { return RANGE_TRANSITION; }
role_transition { return ROLE_TRANSITION; }
optional_policy { return OPTIONAL_POLICY; }
gen_require { return GEN_REQUIRE; }
gen_tunable { return GEN_TUNABLE; }
require { return REQUIRE; }
tunable_policy { return TUNABLE_POLICY; }
ifelse { return IFELSE; }
refpolicywarn { return REFPOLICYWARN; }
class { return CLASS; }
if { return IF; }
else { return ELSE; }
ifdef { return IFDEF; }
ifndef { return IFNDEF; }
genfscon { return GENFSCON; }
sid { return SID; }
portcon { return PORTCON; }
netifcon { return NETIFCON; }
nodecon { return NODECON; }
fs_use_trans { return FS_USE_TRANS; }
fs_use_xattr { return FS_USE_XATTR; }
fs_use_task { return FS_USE_TASK; }
define { return DEFINE; }
gen_user { return GEN_USER; }
gen_context { return GEN_CONTEXT; }
permissive { return PERMISSIVE; }
typebounds { return TYPEBOUNDS; }
interface { return INTERFACE; }
template { return TEMPLATE; }
userdebug_or_eng { return USERDEBUG_OR_ENG; }
s[0-9]+(\.s[0-9]+)?(:c?[0-9]+(.c?[0-9]+)?)? { yylval.string = strdup(yytext); return MLS_LEVEL; }
[0-9]+\.[0-9]+(\.[0-9]+)? { yylval.string = strdup(yytext); return VERSION_NO; }
[0-9]+ { yylval.string = strdup(yytext); return NUMBER; }
[a-zA-Z\$\/][a-zA-Z0-9_\$\*\.\/\-]* { yylval.string = strdup(yytext); return STRING; }
[0-9a-zA-Z\$\/][a-zA-Z0-9_\$\*\.\/\-]* { yylval.string = strdup(yytext); return NUM_STRING; }
\"[a-zA-Z0-9_\.\-\:~]*\" { yylval.string = strdup(yytext); return QUOTED_STRING; }
\( { return OPEN_PAREN; }
\) { return CLOSE_PAREN; }
\, { return COMMA; }
\. { return PERIOD; }
\{ { return OPEN_CURLY; }
\} { return CLOSE_CURLY; }
\: { return COLON; }
\; { return SEMICOLON; }
\` { return BACKTICK; }
\' { return SINGLE_QUOTE; }
\~ { return TILDA; }
\* { return STAR; }
\- { return DASH; }
\&\& { return AND; }
\|\| { return OR; }
\^ { return XOR; }
\! { return NOT; }
\=\= { return EQUAL; }
\!\= { return NOT_EQUAL; }
^\#.*\n { yylineno++; return COMMENT; }
(\#.*)?\n { yylineno++; }
dnl(.*)?\n { yylineno++; }
[ \t] ; /* skip whitespace */
\% { yyerror("Invalid character: %%"); /* will be run through printf again */ }
. { char *str = malloc(strlen(yytext) + 1); sprintf(str, "Invalid character: %s", yytext); yyerror(str); free(str); }

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
