#include <fts.h>
#include <stdio.h>

#include "maps.h"

void load_access_vectors_normal(char *av_path) {

	char ** paths = calloc(2, sizeof(char*));

	paths[0] = av_path;

	FTS *ftsp = fts_open(paths, FTS_PHYSICAL, NULL);

	FTSENT *file = fts_read(ftsp);

	while ( file ) {

		if (file->fts_level != 0 && file->fts_info == FTS_D && 0 != strcmp(file->fts_name, "perms")) {
			// Directory being visited the first time

			insert_into_decl_map(file->fts_name, "class", DECL_CLASS);
		} else if (file->fts_info == FTS_F && 0 != strcmp(file->fts_name, "index")) {
			// File

			insert_into_decl_map(file->fts_name, "perm", DECL_PERM);
		}
		file = fts_read(ftsp);
	}
	fts_close(ftsp);
	free(paths);
}

void load_access_vectors_source() {

}

void load_modules_normal() {

}

static int is_space(char c) {
	return ( c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static char *strip_space(char *str) {

	while (is_space(*str)) {
		str++;
	}

	char *end = str;

	while (!is_space(*end)) {
		end++;
	}

	*end = '\0';

	return str;
}

enum selint_error load_modules_source(char *modules_conf_path) {
	FILE *fd = fopen(modules_conf_path, "r");
	if (!fd) {
		return SELINT_IO_ERROR;
	}

	char *line = NULL;
	size_t len_read = 0;
	size_t buf_len = 0;
	while ((len_read = getline(&line, &buf_len, fd)) != -1) {
		if (len_read <= 1 || line[0] == '#') {
			continue;
		}
		char *pos = strtok(line, "=");
		char *mod_name = strip_space(pos);
		pos = strtok(NULL, "=");
		char *status = strip_space(pos);
		insert_into_mods_map(mod_name, status);
		if (strtok(NULL, "=")) {
			return SELINT_PARSE_ERROR;
		}
	}
	free(line);

	return SELINT_SUCCESS;
}
