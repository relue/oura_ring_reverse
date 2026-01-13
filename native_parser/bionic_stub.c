#include <stdio.h>
#include <stdarg.h>

// Stub for android_set_abort_message (only Bionic-specific symbol needed from libc)
void android_set_abort_message(const char* msg) {
    fprintf(stderr, "[STUB:abort] %s\n", msg);
}

// Stub for __android_log_print (from liblog.so)
int __android_log_print(int prio, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    return 0;
}

// Stub for __android_log_write (from liblog.so)
int __android_log_write(int prio, const char* tag, const char* msg) {
    fprintf(stderr, "[%s] %s\n", tag, msg);
    return 0;
}

// Stub for __android_log_vprint (from liblog.so)
int __android_log_vprint(int prio, const char* tag, const char* fmt, va_list ap) {
    fprintf(stderr, "[%s] ", tag);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    return 0;
}

// Stub for __android_log_assert (from liblog.so)
void __android_log_assert(const char* cond, const char* tag, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ASSERT:%s] %s: ", tag, cond ? cond : "");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
