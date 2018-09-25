#include <stdio.h>
#include "y.tab.h"

extern int yyparse();

int main() {
	yyparse();
	return 0;
}
