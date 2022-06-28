/*
* Copyright 2022 The SELint Contributors
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef XALLOC_H
#define XALLOC_H

#include <stdio.h>
#include <sysexits.h>

#define oom_failure()                                             \
	do {                                                      \
		fprintf(stderr,                                   \
			"Failed to allocate memory [%s():%d]\n",  \
			__func__,                                 \
			__LINE__);                                \
		exit(EX_OSERR);                                   \
	} while(0)

/*********************************************
* Checked malloc wrapper.
*********************************************/
#define xmalloc(size) ({            \
	void *ret_ = malloc(size);  \
	if (!ret_) {                \
		oom_failure();      \
	}                           \
	ret_;                       \
})

/*********************************************
* Checked calloc wrapper.
*********************************************/
#define xcalloc(nmemb, size) ({            \
	void *ret_ = calloc(nmemb, size);  \
	if (!ret_) {                       \
		oom_failure();             \
	}                                  \
	ret_;                              \
})

/*********************************************
* Checked realloc wrapper.
*********************************************/
#define xrealloc(ptr, size) ({            \
	void *ret_ = realloc(ptr, size);  \
	if (!ret_) {                      \
		oom_failure();            \
	}                                 \
	ret_;                             \
})

/*********************************************
* Checked strdup wrapper.
*********************************************/
#define xstrdup(str) ({            \
	void *ret_ = strdup(str);  \
	if (!ret_) {               \
		oom_failure();     \
	}                          \
	ret_;                      \
})

/*********************************************
* Checked strndup wrapper.
*********************************************/
#define xstrndup(str, size) ({            \
	void *ret_ = strndup(str, size);  \
	if (!ret_) {                      \
		oom_failure();            \
	}                                 \
	ret_;                             \
})

#endif /* XALLOC_H */
