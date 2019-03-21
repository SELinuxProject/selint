#include <fts.h>

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
}

void load_access_vectors_source() {

}
