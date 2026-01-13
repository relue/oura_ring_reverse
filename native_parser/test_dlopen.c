#include <stdio.h>
#include <dlfcn.h>

int main() {
    printf("Testing dlopen...\n");
    
    // Try current directory
    void* h = dlopen("./liblog.so", RTLD_NOW);
    if (h) {
        printf("Loaded ./liblog.so OK\n");
        dlclose(h);
    } else {
        printf("Failed ./liblog.so: %s\n", dlerror());
    }
    
    // Try libm from system
    h = dlopen("libm.so.6", RTLD_NOW);
    if (h) {
        printf("Loaded libm.so.6 OK\n");
        dlclose(h);
    } else {
        printf("Failed libm.so.6: %s\n", dlerror());
    }
    
    return 0;
}
