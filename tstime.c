#include "taskstat.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>

int print_time_mem(struct taskstats *t)
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
  return 0;
}

#define CHECK_ERR(a) \
  if (a<0) { \
    fprintf(stderr, "%s:%d ", __FILE__, __LINE__); \
    perror(0); \
    exit(23); \
  }

void child_exit(int i)
{
}

void install_chld_handler()
{
  struct sigaction sa = { 0 };
  sa.sa_handler = child_exit;
  sa.sa_flags = SA_NOCLDSTOP;
  int r = sigaction(SIGCHLD, &sa,  0); CHECK_ERR(r);
}

void wait_for_child(pid_t pid)
{
  int status;
  pid_t r = waitpid(pid, &status, 0); CHECK_ERR(r);
  if (WIFEXITED(status))
    fprintf(stderr, "Exit status: %d\t", WEXITSTATUS(status));
  if (WIFSIGNALED(status))
    fprintf(stderr, "Signal: %d\t", WTERMSIG(status));
  // _BSD_SOURCE
  //if (WCOREDUMP(status))
  //  fprintf(stderr, "coredumped");
  fprintf(stderr, "\n");
}

void help(char *s)
{
  printf("%s COMMAND OPTIONS*\n\n"
      "\texecutes COMMAND and prints its runtime and highwater mem usage\n\n"
      "(uses the taskstat delay accounting API of the Linux Kernel 2.6)\n",
      s);
}

int main(int argc, char **argv)
{
  if (argc == 1) {
    help(argv[0]);
    return 1;
  }
  if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
    help(argv[0]);
    return 0;
  }
  int start_arg = 1;
  dbg = 0;
  //rcvbufsz = 0;

  int r = 0;
  struct ts_t t;
  r = ts_init(&t); CHECK_ERR(r);

  //install_chld_handler();

 
  char cpumask[100];
  int cpus = sysconf(_SC_NPROCESSORS_CONF);
  snprintf(cpumask, 100, "0-%d", cpus);
  PRINTF("#CPUS: %d\n", cpus);
  r = ts_set_cpus(&t, cpumask); CHECK_ERR(r);


  pid_t pid = fork(); CHECK_ERR(pid);
  if (!pid) {
    int r = execvp(argv[start_arg], argv+start_arg); CHECK_ERR(r);
    return 0;
    malloc(10 * 1024 * 1024);
    sleep(2);
    return 0;
  }
  //pause();
  //r = ts_set_pid(&t, pid); CHECK_ERR(r);

  r = ts_wait(&t, pid, print_time_mem); CHECK_ERR(r);
  //r = ts_wait(&t, 0, print_time_mem); CHECK_ERR(r);

  wait_for_child(pid);


  ts_finish(&t);
  return 0;
}

