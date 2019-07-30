#ifndef STARTUP_H
#define STARTUP_H

#include "selint_error.h"

void load_access_vectors_normal(char *av_path);

void load_access_vectors_source();

void load_modules_normal();

enum selint_error load_modules_source(char *modules_conf_path);

#endif
