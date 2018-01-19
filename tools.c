#include "tools.h"

#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>

#define MAX_CPUS 128

void print_taskstats(int fd, struct taskstats* t)
{
  char buf[300];
  int bytes = sprintf(
    buf,
    "%u\n%u\n%u\n%llu\n%llu\n%llu\n%llu\n%llu\n%llu\n"
    "%llu\n%llu\n%llu\n%llu\n%llu\n%llu\n",
    t->ac_pid,
    t->ac_btime,
    t->ac_exitcode,
    t->cpu_run_real_total,
    t->cpu_run_virtual_total,
    t->ac_utime,
    t->ac_stime,
    t->hiwater_vm,
    t->hiwater_rss,
    t->virtmem,
    t->coremem,
    t->read_char,
    t->write_char,
    t->read_bytes,
    t->write_bytes
  );
  write(fd, buf, bytes);
}

void gen_cpumask(char* cpumask, size_t len)
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
