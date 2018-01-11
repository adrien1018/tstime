#ifndef TOOLS_H
#define TOOLS_H

#include <sys/types.h>
#include <sched.h>

struct taskstats;

void pp_taskstats(struct taskstats *t);
void gen_cpumask(char *cpumask, size_t len);
int parse_cpumask(const char* cpumask, cpu_set_t* cpuset);

#define CHECK_ERR(a) \
  if (a<0) { \
    fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
    perror(0); \
    exit(23); \
  }

#define CHECK_ERR_SIMPLE(a) \
  if (a<0) { \
    fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
    exit(23); \
  }

#define LOG(stream, fmt, arg...) { \
  fprintf(stream, fmt, ##arg); \
}

#endif
