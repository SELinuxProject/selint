/*
* Copyright 2020 The SELint Contributors
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "perm_macro.h"
#include "color.h"
#include "maps.h"
#include "util.h"
#include "xalloc.h"

typedef uint32_t mask_t;

struct perm_macro {
	struct perm_macro *next;
	char *name;
	mask_t mask_raw;
};

static bool initialized = false;

static struct perm_macro *dir_macros = NULL;
static struct perm_macro *file_macros = NULL;
static struct perm_macro *lnk_file_macros = NULL;
static struct perm_macro *chr_file_macros = NULL;
static struct perm_macro *blk_file_macros = NULL;
static struct perm_macro *sock_file_macros = NULL;
static struct perm_macro *fifo_file_macros = NULL;

enum pm_common_file {
	PM_CF__EMPTY		=         0u,
	PM_CF_IOCTL		= (1u <<  1),
	PM_CF_READ		= (1u <<  2),
	PM_CF_WRITE		= (1u <<  3),
	PM_CF_CREATE		= (1u <<  4),
	PM_CF_GETATTR		= (1u <<  5),
	PM_CF_SETATTR		= (1u <<  6),
	PM_CF_LOCK		= (1u <<  7),
	PM_CF_RELABELFROM	= (1u <<  8),
	PM_CF_RELABELTO		= (1u <<  9),
	PM_CF_APPEND		= (1u << 10),
	PM_CF_MAP		= (1u << 11),
	PM_CF_UNLINK		= (1u << 12),
	PM_CF_LINK		= (1u << 13),
	PM_CF_RENAME		= (1u << 14),
	PM_CF_EXECUTE		= (1u << 15),
	PM_CF_MOUNTON		= (1u << 16),
	PM_CF_OPEN		= (1u << 17),
	PM_CF_WATCH		= (1u << 18),

	// dir perms
	PM_CF_ADDNAME		= (1u << 19),
	PM_CF_REMOVENAME	= (1u << 20),
	PM_CF_REPARENT		= (1u << 21),
	PM_CF_SEARCH		= (1u << 23),
	PM_CF_RMDIR		= (1u << 24),

	// file perms
	PM_CF_EXECNOTRANS	= (1u << 25),
	PM_CF_ENTRYPOINT	= (1u << 26),

	// perms not covered by macros
	PM_CF__UNCOVERED	= (1u << 31),

	// extended permissions
	// these flags contain the original raw permission flag or'ed with
	// flags of permissions that are reasonable extendable
	//   e.g. open extends getattr and write extends append
	PM_CF_IOCTL_X		= PM_CF_IOCTL,
	PM_CF_GETATTR_X		= PM_CF_GETATTR,
	PM_CF_READ_X		= PM_CF_READ | PM_CF_IOCTL | PM_CF_GETATTR | PM_CF_SEARCH | PM_CF_LOCK,
	PM_CF_LOCK_X		= PM_CF_LOCK | PM_CF_GETATTR,
	PM_CF_APPEND_X		= PM_CF_APPEND | PM_CF_GETATTR,
	PM_CF_WRITE_X		= PM_CF_WRITE | PM_CF_IOCTL | PM_CF_GETATTR | PM_CF_APPEND | PM_CF_LOCK,
	PM_CF_CREATE_X		= PM_CF_CREATE | PM_CF_GETATTR | PM_CF_LINK,
	PM_CF_SETATTR_X		= PM_CF_SETATTR | PM_CF_GETATTR,
	PM_CF_MAP_X		= PM_CF_MAP | PM_CF_IOCTL | PM_CF_GETATTR,
	PM_CF_UNLINK_X		= PM_CF_UNLINK | PM_CF_GETATTR | PM_CF_RMDIR,
	PM_CF_LINK_X		= PM_CF_LINK | PM_CF_GETATTR,
	PM_CF_RENAME_X		= PM_CF_RENAME | PM_CF_GETATTR,
	PM_CF_OPEN_X		= PM_CF_OPEN | PM_CF_GETATTR,
	PM_CF_EXECUTE_X		= PM_CF_EXECUTE | PM_CF_READ | PM_CF_GETATTR | PM_CF_MAP,
	PM_CF_RELABELFROM_X	= PM_CF_RELABELFROM | PM_CF_GETATTR,
	PM_CF_RELABELTO_X	= PM_CF_RELABELTO | PM_CF_GETATTR,
	PM_CF_MOUNTON_X		= PM_CF_MOUNTON | PM_CF_GETATTR,
	PM_CF_WATCH_X		= PM_CF_WATCH | PM_CF_READ,
	PM_CF_ADDNAME_X		= PM_CF_ADDNAME | PM_CF_WRITE_X,
	PM_CF_REMOVENAME_X	= PM_CF_REMOVENAME | PM_CF_WRITE_X,
	PM_CF_REPARENT_X	= PM_CF_REPARENT | PM_CF_GETATTR,
	PM_CF_SEARCH_X		= PM_CF_SEARCH | PM_CF_GETATTR,
	PM_CF_RMDIR_X		= PM_CF_RMDIR | PM_CF_UNLINK_X,
	PM_CF_EXECNOTRANS_X	= PM_CF_EXECNOTRANS | PM_CF_EXECUTE_X,
	PM_CF_ENTRYPOINT_X	= PM_CF_ENTRYPOINT,
	PM_CF__UNCOVERED_X	= PM_CF__UNCOVERED,
};

struct pm_ltable {
	const char *string;
	enum pm_common_file flag_raw;
	enum pm_common_file flag_extended;
};

static const struct pm_ltable pm_ltable_common_file[] = {
	{ "ioctl",		PM_CF_IOCTL,		PM_CF_IOCTL_X },
	{ "read",		PM_CF_READ,		PM_CF_READ_X },
	{ "write",		PM_CF_WRITE,		PM_CF_WRITE_X },
	{ "create",		PM_CF_CREATE,		PM_CF_CREATE_X },
	{ "getattr",		PM_CF_GETATTR,		PM_CF_GETATTR_X },
	{ "setattr",		PM_CF_SETATTR,		PM_CF_SETATTR_X },
	{ "lock",		PM_CF_LOCK,		PM_CF_LOCK_X },
	{ "relabelfrom",	PM_CF_RELABELFROM,	PM_CF_RELABELFROM_X },
	{ "relabelto",		PM_CF_RELABELTO,	PM_CF_RELABELTO_X },
	{ "append",		PM_CF_APPEND,		PM_CF_APPEND_X },
	{ "map",		PM_CF_MAP,		PM_CF_MAP_X },
	{ "unlink",		PM_CF_UNLINK,		PM_CF_UNLINK_X },
	{ "link",		PM_CF_LINK,		PM_CF_LINK_X },
	{ "rename",		PM_CF_RENAME,		PM_CF_RENAME_X },
	{ "execute",		PM_CF_EXECUTE,		PM_CF_EXECUTE_X },
	{ "mounton",		PM_CF_MOUNTON,		PM_CF_MOUNTON_X },
	{ "open",		PM_CF_OPEN,		PM_CF_OPEN_X },
	{ "watch",		PM_CF_WATCH,		PM_CF_WATCH_X },

	// dir perms
	{ "add_name",		PM_CF_ADDNAME,		PM_CF_ADDNAME_X },
	{ "remove_name",	PM_CF_REMOVENAME,	PM_CF_REMOVENAME_X },
	{ "reparent",		PM_CF_REPARENT,		PM_CF_REPARENT_X },
	{ "search",		PM_CF_SEARCH,		PM_CF_SEARCH_X },
	{ "rmdir",		PM_CF_RMDIR,		PM_CF_RMDIR_X },

	// file perms
	{ "execute_no_trans",	PM_CF_EXECNOTRANS,	PM_CF_EXECNOTRANS_X },
	{ "entrypoint",		PM_CF_ENTRYPOINT,	PM_CF_ENTRYPOINT_X },

	// uncovered perms
	{ "quotaon",		PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "audit_access",	PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "execmod",		PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "watch_mount",	PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "watch_sb",		PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "watch_with_perm",	PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
	{ "watch_reads",	PM_CF__UNCOVERED,	PM_CF__UNCOVERED_X },
};

unsigned short popcount(mask_t mask);
void compute_perm_mask(const struct string_list *permissions, mask_t *mask_raw, mask_t *mask_extended);

static void str_to_mask(const char *permission, mask_t *mask_raw, mask_t *mask_extended)
{
	for (size_t i = 0; i < (sizeof pm_ltable_common_file / sizeof *pm_ltable_common_file); ++i) {
		if (0 == strcmp(permission, pm_ltable_common_file[i].string)) {
			*mask_raw |= pm_ltable_common_file[i].flag_raw;
			*mask_extended |= pm_ltable_common_file[i].flag_extended;
			return;
		}
	}

	const struct string_list *macro_perms = look_up_in_permmacros_map(permission);
	if (macro_perms) {
		compute_perm_mask(macro_perms, mask_raw, mask_extended);
		return;
	}

	// treat unknown permission as uncovered
	*mask_raw |= PM_CF__UNCOVERED;
	*mask_extended |= PM_CF__UNCOVERED;
}

void compute_perm_mask(const struct string_list *permissions, mask_t *mask_raw, mask_t *mask_extended)
{
	for (; permissions; permissions = permissions->next) {
		str_to_mask(permissions->string, mask_raw, mask_extended);
	}
}

struct string_builder {
	char *mem;
	size_t len;
	size_t cap;
};

static struct string_builder *sb_create(size_t init_cap)
{
	if (init_cap == 0) {
		init_cap = 32;
	}

	struct string_builder *ret = xmalloc(sizeof(struct string_builder));
	ret->mem = xmalloc(sizeof(char) * init_cap);
	ret->mem[0] = '\0';
	ret->len = 0;
	ret->cap = init_cap;

	return ret;
}

static void sb_destroy(struct string_builder *sb)
{
	if (sb == NULL) {
		return;
	}

	free(sb->mem);
	free(sb);
}

static void sb_append_strn(struct string_builder *sb, const char *str, size_t len)
{
	while (sb->len + len + 1 > sb->cap) {
		sb->mem = xrealloc(sb->mem, 2 * sb->cap);
		sb->cap = 2 * sb->cap;
	}

	memcpy(sb->mem + sb->len, str, len);
	sb->len += len;
	sb->mem[sb->len] = '\0';
}

static void sb_append_str(struct string_builder *sb, const char *str)
{
	sb_append_strn(sb, str, strlen(str));
}

static char *sb_decouple_str(struct string_builder *sb)
{
	char *ret = sb->mem;
	sb->mem = NULL;
	sb_destroy(sb);

	return ret;
}

static char *mask_to_str(mask_t mask)
{
	struct string_builder *sb = sb_create(0);

	if (mask == PM_CF__EMPTY) {
		sb_append_str(sb, "(none)");
		return sb_decouple_str(sb);
	}

	if (mask & PM_CF__UNCOVERED) {
		printf("%sInternal Error%s: mask_to_str() called with unsupported permission\n", color_error(), color_reset());
		sb_append_str(sb, "(unsupported perm)");
		return sb_decouple_str(sb);
	}

	sb_append_str(sb, "{ ");

	for (size_t i = 0; i < (sizeof pm_ltable_common_file / sizeof *pm_ltable_common_file); ++i) {
		if (mask & pm_ltable_common_file[i].flag_raw) {
			sb_append_str(sb, pm_ltable_common_file[i].string);
			sb_append_str(sb, " ");
			mask &= (mask_t)(~pm_ltable_common_file[i].flag_raw);
		}
	}

	sb_append_str(sb, "}");

	return sb_decouple_str(sb);
}

static char *permission_strings_matched_str(const struct string_list *permissions, mask_t mask)
{
	struct string_builder *sb = sb_create(0);

	sb_append_str(sb, "{ ");

	for (; permissions; permissions = permissions->next) {
		mask_t mask_raw = 0, mask_extended = 0;
		str_to_mask(permissions->string, &mask_raw, &mask_extended);
		if ((mask_raw & mask) == mask_raw) {
			sb_append_str(sb, permissions->string);
			sb_append_str(sb, " ");
		}
	}

	sb_append_str(sb, "}");

	return sb_decouple_str(sb);
}

static unsigned short permission_strings_matched_count(const struct string_list *permissions, mask_t mask)
{
	unsigned short count = 0;

	for (; permissions; permissions = permissions->next) {
		mask_t mask_raw = 0, mask_extended = 0;
		str_to_mask(permissions->string, &mask_raw, &mask_extended);
		if ((mask_raw & mask) == mask_raw) {
			count++;
		}
	}

	return count;
}

unsigned short popcount(mask_t mask)
{
	unsigned short c = 0;
	for (; mask != 0; mask &= mask - 1) {
		c++;
	}
	return c;
}

static void load_permission_macro(const char *name, const struct string_list *permissions)
{
	mask_t mask_raw = PM_CF__EMPTY;
	mask_t mask_extended = PM_CF__EMPTY;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	// skip macros containing uncovered permissions
	if (mask_raw & PM_CF__UNCOVERED) {
		return;
	}

	struct perm_macro **category;
	if (ends_with(name, strlen(name), "_dir_perms", strlen("_dir_perms"))) {
		category = &dir_macros;
	} else if (ends_with(name, strlen(name), "_lnk_file_perms", strlen("_lnk_file_perms"))) {
		category = &lnk_file_macros;
	} else if (ends_with(name, strlen(name), "_chr_file_perms", strlen("_chr_file_perms"))) {
		category = &chr_file_macros;
	} else if (ends_with(name, strlen(name), "_term_perms", strlen("_term_perms"))) {
		category = &chr_file_macros;
	} else if (ends_with(name, strlen(name), "_blk_file_perms", strlen("_blk_file_perms"))) {
		category = &blk_file_macros;
	} else if (ends_with(name, strlen(name), "_sock_file_perms", strlen("_sock_file_perms"))) {
		category = &sock_file_macros;
	} else if (ends_with(name, strlen(name), "_fifo_file_perms", strlen("_fifo_file_perms"))) {
		category = &fifo_file_macros;
	} else if (ends_with(name, strlen(name), "_file_perms", strlen("_file_perms"))) {
		category = &file_macros;
	} else {
		// macro for unsupported class
		return;
	}

	struct perm_macro *tmp = xmalloc(sizeof(struct perm_macro));
	tmp->name = xstrdup(name);
	tmp->mask_raw = mask_raw;

	// first entry
	if (*category == NULL) {
		tmp->next = NULL;
		*category = tmp;
		return;
	}

	// sort the permission-macro-list ascending by number of permissions
	const unsigned short tmp_count_raw = popcount(tmp->mask_raw);
	struct perm_macro *cur = *category, *prev = NULL;
	for (;;) {
		if (tmp_count_raw < popcount(cur->mask_raw)) {
			if (prev == NULL) {
				tmp->next = cur;
				*category = tmp;
			} else {
				tmp->next = cur;
				prev->next = tmp;
			}
			return;
		}

		if (cur->next == NULL) {
			tmp->next = NULL;
			cur->next = tmp;
			return;
		}

		prev = cur;
		cur = cur->next;
	}
}

char *permmacro_check(const char *class, const struct string_list *permissions)
{
	if (!initialized) {
		visit_all_in_permmacros_map(load_permission_macro);

		initialized = true;
	}

	const struct perm_macro *category;
	if (0 == strcmp(class, "dir")) {
		category = dir_macros;
	} else if (0 == strcmp(class, "file")) {
		category = file_macros;
	} else if (0 == strcmp(class, "lnk_file")) {
		category = lnk_file_macros;
	} else if (0 == strcmp(class, "chr_file")) {
		category = chr_file_macros;
	} else if (0 == strcmp(class, "blk_file")) {
		category = blk_file_macros;
	} else if (0 == strcmp(class, "sock_file")) {
		category = sock_file_macros;
	} else if (0 == strcmp(class, "fifo_file")) {
		category = fifo_file_macros;
	} else {
		// unsupported class
		return NULL;
	}

	mask_t mask_raw = PM_CF__EMPTY, mask_extended = PM_CF__EMPTY;
	compute_perm_mask(permissions, &mask_raw, &mask_extended);

	// ignore av rules containing at most one recognized permission
	if (popcount(mask_raw & ~PM_CF__UNCOVERED) < 2) {
		return NULL;
	}

	// special extending rules
	{
		// extend setattr on create AND write
		if (mask_extended & (PM_CF_CREATE | PM_CF_WRITE)) {
			mask_extended |= PM_CF_SETATTR_X;
		}

		// extend rename/reparent on create AND unlink/rmdir
		// (rmdir extends unlink, so PM_CF_UNLINK is set iff PM_CF_RMDIR is set)
		if (mask_extended & (PM_CF_CREATE | PM_CF_UNLINK)) {
			mask_extended |= (PM_CF_RENAME_X | PM_CF_REPARENT_X);
		}
	}

	const char *best_name = NULL;
	unsigned short best_coverage = 0;
	unsigned short best_extending = 0;
	mask_t best_mask_raw;
	for (const struct perm_macro *cur = category; cur; cur= cur->next) {
		// ignore macros covering additional non-extended permissions
		if (cur->mask_raw & ~mask_extended) {
			continue;
		}

		const unsigned short coverage = popcount(cur->mask_raw & mask_raw);
		// ignore macros covering only one used permission
		if (coverage < 2) {
			continue;
		}

		// ignore macros with less coverage than best yet match
		if (coverage < best_coverage) {
			continue;
		}

		const unsigned short extending = popcount(cur->mask_raw & ~mask_raw);
		// ignore macros with equal coverage but more extended permissions
		if (coverage == best_coverage && extending > best_extending) {
			continue;
		}

		// ignore macros replacing only one permission string,
		// e.g. { map read_file_perms } should not suggest mmap_read_file_perms replacing { map }
		// cause read_file_perms include { lock } but mmap_read_file_perms not
		if (permission_strings_matched_count(permissions, cur->mask_raw & mask_raw) < 2) {
			continue;
		}

		best_name = cur->name;
		best_coverage = coverage;
		best_mask_raw = cur->mask_raw;
		best_extending = extending;
	}

	// no macro match found
	if (!best_name) {
		return NULL;
	}

	// matched macro already used
	// we match read_file_perms for { read_file_perms }, because its the best match
	// and we do not discard it prior, cause we do not want to suggest search_dir_perms on list_dir_perms
	if (str_in_sl(best_name, permissions)) {
		return NULL;
	}

	char *perms_added = mask_to_str(best_mask_raw & ~mask_raw);
	char *perms_matched = permission_strings_matched_str(permissions, best_mask_raw & mask_raw);
#define MSG_STR "Suggesting permission macro: %s (replacing %s, would add %s)"
	size_t len = (size_t)snprintf(NULL, 0, MSG_STR, best_name, perms_matched, perms_added);
	char *ret = xmalloc(len + 1);
	snprintf(ret, len + 1, MSG_STR, best_name, perms_matched, perms_added);
#undef MSG_STR
	free(perms_matched);
	free(perms_added);

	return ret;
}

static void free_perm_macro(struct perm_macro *to_free)
{
	while (to_free) {
		struct perm_macro *tmp = to_free->next;

		free(to_free->name);
		free(to_free);

		to_free = tmp;
	}
}

void free_permmacros()
{
	initialized = false;

	free_perm_macro(dir_macros);
	free_perm_macro(file_macros);
	free_perm_macro(lnk_file_macros);
	free_perm_macro(chr_file_macros);
	free_perm_macro(blk_file_macros);
	free_perm_macro(sock_file_macros);
	free_perm_macro(fifo_file_macros);

	dir_macros = NULL;
	file_macros = NULL;
	lnk_file_macros = NULL;
	chr_file_macros = NULL;
	blk_file_macros = NULL;
	sock_file_macros = NULL;
	fifo_file_macros = NULL;
}
