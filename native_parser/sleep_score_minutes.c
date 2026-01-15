/*
 * sleep_score_minutes.c - Sleep Score using native stateless function
 * Usage: sleep_score_minutes_ndk "total,deep,rem,light,eff,latency,wakeups,awake,restless,temp,gotup,midpoint"
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>

typedef struct { uint8_t data[64]; } output_t;
typedef int (*calc_t)(output_t*, uint16_t, uint16_t, uint16_t, uint16_t, uint8_t, uint8_t, uint8_t, uint16_t, uint8_t, int16_t, uint8_t, int);
typedef void (*init_t)(uint8_t);

int main(int argc, char* argv[]) {
    void* h = dlopen("libappecore.so", RTLD_NOW);
    calc_t calc = (calc_t)dlsym(h, "_Z35ecore_sleep_score_calculate_minutesP19s_sleep_summary_4_tttthhhthshi");
    init_t init = (init_t)dlsym(h, "_Z29ecore_sleep_score_init_limitsh");

    int a=420, b=84, c=105, d=231, e=88, f=10, g=2, hh=300, ii=4, j=0, k=0, m=10800;

    if (argc > 1) {
        sscanf(argv[1], "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f, &g, &hh, &ii, &j, &k, &m);
    }

    if (init) init(100);
    output_t out = {0};
    int s = calc(&out, (uint16_t)a,(uint16_t)b,(uint16_t)c,(uint16_t)d,(uint8_t)e,(uint8_t)f,(uint8_t)g,(uint16_t)hh,(uint8_t)ii,(int16_t)j,(uint8_t)k,m);

    /* Output for Python wrapper */
    printf("sleepScore\n%d\n", s);
    printf("contributors\n%d,%d,%d,%d,%d,%d\n", out.data[0], out.data[1], out.data[2], out.data[3], out.data[5], out.data[6]);
    printf("qualityFlag\n%d\n", out.data[4]);

    dlclose(h);
    return 0;
}
