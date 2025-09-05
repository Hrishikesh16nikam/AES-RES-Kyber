// check https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
// for detialed usage
static __inline__ uint64_t timer_start(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("CPUID\n\t"
               "RDTSC\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax", "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}

static __inline__ uint64_t timer_stop(void)
{
  unsigned cycles_low, cycles_high;
  asm volatile("RDTSCP\n\t"
               "mov %%edx, %0\n\t"
               "mov %%eax, %1\n\t"
               "CPUID\n\t"
               : "=r"(cycles_high), "=r"(cycles_low)::"%rax",
                 "%rbx", "%rcx", "%rdx");
  return ((uint64_t)cycles_high << 32) | cycles_low;
}
