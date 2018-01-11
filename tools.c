#include "tools.h"

#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>

#define MAX_CPUS 128

void pp_taskstats(struct taskstats *t)
{
  time_t btime = t->ac_btime;
  printf("\npid: %u (%s) started: %s"
      "\treal %7.3f s, user %7.3f s, sys %7.3fs\n"
      "\trss %8llu kb, vm %8llu kb\n\n",
      t->ac_pid, t->ac_comm, ctime(&btime),
      t->ac_etime / 1000000.0,
      t->ac_utime / 1000000.0,
      t->ac_stime / 1000000.0,
      (unsigned long long) t->hiwater_rss,
      (unsigned long long) t->hiwater_vm

      );
}

void gen_cpumask(char *cpumask, size_t len)
{
  int cpus = sysconf(_SC_NPROCESSORS_CONF) - 1;
  snprintf(cpumask, len, "0-%d", cpus);
}

void add_cpumask_item(int first, int last, cpu_set_t* cpuset)
{
  if (first == -1) CPU_SET(last, cpuset);
  else
    for (int i = first; i <= last; i++) CPU_SET(i, cpuset);
}

int parse_cpumask(const char* cpumask, cpu_set_t* cpuset)
{
  CPU_ZERO(cpuset);
  int now = 0, start = -1, flag = 0;
  for (const char* i = cpumask; *i; i++) {
    if (*i == ',') {
      if (!flag || start > now) return -1;
      add_cpumask_item(start, now, cpuset);
      flag = now = 0;
      start = -1;
    }
    else if (*i == '-') {
      if (start != -1 || !flag) return -1;
      start = now;
      flag = now = 0;
    }
    else if (*i >= '0' && *i <= '9') {
      now = now * 10 + (*i ^ '0');
      if (now >= MAX_CPUS) return -1;
      flag = 1;
    }
    else return -1;
  }
  if (!flag || start > now) return -1;
  add_cpumask_item(start, now, cpuset);
  return 0;
}
