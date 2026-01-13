#include <stdio.h>
#include <dlfcn.h>

int main() {
    printf("Testing dlopen with Android libraries...\n");
    
    // First try liblog.so (our stub)
    void* h = dlopen("liblog.so", RTLD_NOW);
    if (h) {
        printf("Loaded liblog.so OK\n");
    } else {
        printf("Failed liblog.so: %s\n", dlerror());
        return 1;
    }
    
    // Try protobuf
    printf("Trying libprotobuf-lite.so...\n");
    void* proto = dlopen("libprotobuf-lite.so", RTLD_NOW | RTLD_GLOBAL);
    if (proto) {
        printf("Loaded libprotobuf-lite.so OK!\n");
    } else {
        printf("Failed libprotobuf-lite.so: %s\n", dlerror());
        return 1;
    }
    
    // Try parser
    printf("Trying libringeventparser.so...\n");
    void* parser = dlopen("libringeventparser.so", RTLD_NOW);
    if (parser) {
        printf("Loaded libringeventparser.so OK!\n");
        
        // Try finding rep_parseEvents
        void* fn = dlsym(parser, "rep_parseEvents");
        if (fn) {
            printf("Found rep_parseEvents at %p\n", fn);
        } else {
            printf("rep_parseEvents not found: %s\n", dlerror());
        }
    } else {
        printf("Failed libringeventparser.so: %s\n", dlerror());
        return 1;
    }
    
    printf("\nAll libraries loaded successfully!\n");
    return 0;
}
