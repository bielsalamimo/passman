#ifndef _PROGRAM_H
#define _PROGRAM_H

#include "Option.h"

typedef struct {
    char *name;
    char *version;
    char *usage;
    size_t options_size;
    Option *options;
} Program;

#endif // _PROGRAM_H
