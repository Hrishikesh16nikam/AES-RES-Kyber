#include "timer.h"

uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

double elapsed_sec(uint64_t start, uint64_t end, double ghz) {
    if (end < start) return 0.0;
    double cycles = (double)(end - start);
    return cycles / (ghz * 1e9);
}
