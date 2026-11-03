#ifndef FW_STDLIB_H
#define FW_STDLIB_H
#include <stddef.h>
void* malloc(size_t n); void free(void* p); void* realloc(void* p, size_t n);
void abort(void);
#endif
