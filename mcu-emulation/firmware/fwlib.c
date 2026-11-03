/* Minimal C runtime for the bare-metal benchmark firmware. */
#include <stddef.h>
#include <stdint.h>
#include "inc/string.h"

void* memcpy(void* d, const void* s, size_t n) {
    uint8_t* dp = d; const uint8_t* sp = s;
    if ((((uintptr_t)dp | (uintptr_t)sp) & 3) == 0) {
        while (n >= 4) { *(uint32_t*)dp = *(const uint32_t*)sp; dp += 4; sp += 4; n -= 4; }
    }
    while (n--) *dp++ = *sp++;
    return d;
}
void* memmove(void* d, const void* s, size_t n) {
    uint8_t* dp = d; const uint8_t* sp = s;
    if (dp == sp || n == 0) return d;
    if (dp < sp || dp >= sp + n) return memcpy(d, s, n);
    while (n--) dp[n] = sp[n];
    return d;
}
void* memset(void* d, int c, size_t n) {
    uint8_t* dp = d; uint8_t b = (uint8_t)c;
    if (((uintptr_t)dp & 3) == 0) {
        uint32_t w = b * 0x01010101u;
        while (n >= 4) { *(uint32_t*)dp = w; dp += 4; n -= 4; }
    }
    while (n--) *dp++ = b;
    return d;
}
int memcmp(const void* a, const void* b, size_t n) {
    const uint8_t *x = a, *y = b;
    for (; n; --n, ++x, ++y) if (*x != *y) return *x - *y;
    return 0;
}
void* memchr(const void* s, int c, size_t n) { const uint8_t* p = s; for (; n; --n, ++p) if (*p == (uint8_t)c) return (void*)p; return 0; }
size_t strlen(const char* s) { size_t n = 0; while (s[n]) ++n; return n; }
char* strncpy(char* d, const char* s, size_t n) { size_t i = 0; for (; i < n && s[i]; ++i) d[i] = s[i]; for (; i < n; ++i) d[i] = 0; return d; }
char* strcpy(char* d, const char* s) { char* r = d; while ((*d++ = *s++)); return r; }
int strcmp(const char* a, const char* b) { while (*a && *a == *b) { ++a; ++b; } return (uint8_t)*a - (uint8_t)*b; }
int strncmp(const char* a, const char* b, size_t n) { for (; n; --n, ++a, ++b) { if (*a != *b) return (uint8_t)*a - (uint8_t)*b; if (!*a) break; } return 0; }
char* strchr(const char* s, int c) { for (;; ++s) { if (*s == (char)c) return (char*)s; if (!*s) return 0; } }
char* strstr(const char* h, const char* n) { size_t l = strlen(n); for (; *h; ++h) if (!strncmp(h, n, l)) return (char*)h; return l ? 0 : (char*)h; }
char* strncat(char* d, const char* s, size_t n) { char* r = d; d += strlen(d); while (n-- && *s) *d++ = *s++; *d = 0; return r; }

/* Bump allocator with a mark/reset point set by the host between operations. */
#define HEAP_SIZE (256 * 1024)
static uint8_t heap[HEAP_SIZE] __attribute__((aligned(8)));
static size_t heap_top = 0, heap_mark = 0;
volatile uint32_t fw_heap_peak = 0;
typedef struct { size_t n; size_t pad; } hdr_t;
void* XMALLOC(size_t n, void* h, int t) {
    (void)h; (void)t;
    size_t need = (sizeof(hdr_t) + n + 7) & ~(size_t)7;
    if (heap_top + need > HEAP_SIZE) return 0;
    hdr_t* p = (hdr_t*)(heap + heap_top); p->n = n; heap_top += need;
    if (heap_top > fw_heap_peak) fw_heap_peak = heap_top;
    return p + 1;
}
void XFREE(void* p, void* h, int t) { (void)p; (void)h; (void)t; }
void* XREALLOC(void* p, size_t n, void* h, int t) {
    void* q = XMALLOC(n, h, t);
    if (p && q) { size_t o = ((hdr_t*)p - 1)->n; memcpy(q, p, o < n ? o : n); }
    return q;
}
void* malloc(size_t n) { return XMALLOC(n, 0, 0); }
void free(void* p) { (void)p; }
void* realloc(void* p, size_t n) { return XREALLOC(p, n, 0, 0); }
void fw_heap_set_mark(void) { heap_mark = heap_top; }
void fw_heap_reset(void) { heap_top = heap_mark; }

/* Stand-in for the MCU's hardware TRNG (one register read per word). */
static uint32_t rng_s = 0x12345678u;
int fw_rng_block(unsigned char* out, unsigned int sz) {
    while (sz) {
        rng_s ^= rng_s << 13; rng_s ^= rng_s >> 17; rng_s ^= rng_s << 5;
        uint32_t w = rng_s;
        for (int i = 0; i < 4 && sz; ++i, --sz) { *out++ = (uint8_t)w; w >>= 8; }
    }
    return 0;
}
volatile uint32_t fw_abort_flag = 0;
void abort(void) { fw_abort_flag = 1; for (;;) __asm__ volatile("bkpt #1"); }
void __aeabi_unwind_cpp_pr0(void) {}
