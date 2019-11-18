#ifndef STARTUP_H
#define STARTUP_H

#include "selint_error.h"
#include "file_list.h"

void load_access_vectors_normal(char *av_path);

void load_access_vectors_source();

void load_modules_normal();

enum selint_error load_modules_source(char *modules_conf_path);

enum selint_error mark_transform_interfaces(struct policy_file_list *files);

#endif
