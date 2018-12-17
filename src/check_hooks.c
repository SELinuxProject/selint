#include <stdlib.h>

#include "check_hooks.h"

void free_check_result(struct check_result *res) {
	free(res->message);
	free(res);
}
