#ifndef TASKSTAT_H
#define TASKSTAT_H

#include <stdint.h>
#include <sys/types.h>

struct taskstats;

struct ts_t {
  int nl_sd;
  uint16_t id;
  uint32_t mypid;
  char *cpumask;
};

typedef struct ts_t ts_t;

int ts_init(ts_t *t);
int ts_set_cpus(ts_t *t, char *cpumask);
int ts_set_pid(ts_t *t, pid_t tid);
int ts_wait(ts_t *t, pid_t pid, struct taskstats* ts_ret);
void ts_finish(ts_t *t);

#endif
