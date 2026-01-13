/*
 * bionic_libc_stub.c - Stub for Bionic libc functions not in glibc
 *
 * Android's Bionic uses different symbol versions (@LIBC) than glibc (@GLIBC_x.x).
 * This stub provides Bionic-specific functions and aliases glibc functions with
 * Bionic's version tags.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <wchar.h>
#include <locale.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/auxv.h>

// ============================================
// Bionic-specific functions
// ============================================

// Bionic's android_set_abort_message
void android_set_abort_message(const char* msg) {
    fprintf(stderr, "[STUB:abort] %s\n", msg);
}

// Bionic's __assert2 (different from glibc's __assert_fail)
void __assert2(const char* file, int line, const char* func, const char* expr) {
    fprintf(stderr, "Assertion failed: %s, file %s, line %d, function %s\n",
            expr, file, line, func);
    abort();
}

// Bionic's __errno (returns pointer to errno)
int* __errno(void) {
    return &errno;
}

// ============================================
// Symbol versioning for Bionic compatibility
// ============================================

// Create aliases for common functions with @LIBC version
// These redirect Bionic symbols to glibc implementations

#define BIONIC_ALIAS(func) \
    __asm__(".symver " #func "_bionic, " #func "@LIBC"); \
    extern typeof(func) func##_bionic __attribute__((alias(#func)));

// For functions that work the same in both
// We create versioned symbols pointing to the real functions

// Note: This approach has limitations. A more robust solution would be libhybris.

// ============================================
// Wrapper declarations for debugging
// ============================================

// These are just to help identify what's being called
__attribute__((constructor))
void bionic_stub_init(void) {
    // fprintf(stderr, "[bionic_stub] Initialized\n");
}
