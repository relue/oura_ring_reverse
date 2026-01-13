/*
 * libc_stub.c - Stub for Bionic-specific libc functions
 *
 * This provides android_set_abort_message which is the only
 * Bionic-specific symbol needed from libc.so
 */

#include <stdio.h>

// Stub for android_set_abort_message (Bionic-specific)
void android_set_abort_message(const char* msg) {
    fprintf(stderr, "[STUB:abort] %s\n", msg);
}
