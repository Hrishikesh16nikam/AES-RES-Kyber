#ifndef TIMER_H
#define TIMER_H
#include <stdint.h>

uint64_t rdtsc(void);
double elapsed_sec(uint64_t start, uint64_t end, double ghz);

#endif
