/*
 * Copyright Georg Sauthoff 2009, GPLv2+
 */

#include "taskstat.h"
#include "tools.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <sched.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>

#include <sys/prctl.h>

void child_exit(int i)
{
}

void install_chld_handler()
{
  struct sigaction sa = { 0 };
  sa.sa_handler = child_exit;
  sa.sa_flags = SA_NOCLDSTOP;
  int r = sigaction(SIGCHLD, &sa, 0); CHECK_ERR(r);
}

int wait_for_child(pid_t pid)
{
  LOG(stderr, "\n");
  int code = 42;
  int status;
  pid_t r = waitpid(pid, &status, 0); CHECK_ERR(r);
  if (WIFEXITED(status)) {
    LOG(stderr, "Exit status: %d\t", WEXITSTATUS(status));
    code = WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status))
    LOG(stderr, "Signal: %d\t", WTERMSIG(status));
  // _BSD_SOURCE
  //if (WCOREDUMP(status))
  //  fprintf(stderr, "coredumped");
  LOG(stderr, "\n");
  return code;
}

void help(char *s)
{
  printf("%s options* [COMMAND OPTIONS] *\n\n"
      "\texecutes COMMAND and prints its runtime and highwater mem usage\n\n"
      "\t-m [CPU mask]\tSet the CPU affinity mask of the program to execute\n"
      "\t-w [PID]\tWait for a specific PID\n"
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
  cpu_set_t cpumask;
  char* cpumask_str;
  if (!strcmp(argv[1], "-m")) {
    if (argc <= 3) {
      help(argv[0]);
      return 1;
    }
    if (parse_cpumask(argv[2], &cpumask) < 0) {
      fprintf(stderr, "Invalid CPU mask.\n");
      return 1;
    }
    cpumask_str = argv[2];
    start_arg += 2;
  }
  else {
    cpumask_str = (char*)malloc(16);
    gen_cpumask(cpumask_str, 16);
    parse_cpumask(cpumask_str, &cpumask);
  }

  int run = 1, waitpid = 0;
  if (!strcmp(argv[start_arg], "-w")) {
    if (argc != start_arg + 2) {
      help(argv[0]);
      return 1;
    }
    sscanf(argv[start_arg + 1], "%d", &waitpid);
    run = 0;
  }

  dbg = 0;

  int r = 0;
  struct ts_t t;
  r = ts_init(&t); CHECK_ERR_SIMPLE(r);

  //install_chld_handler();
  r = ts_set_cpus(&t, cpumask_str); CHECK_ERR(r);

  struct taskstats ts;
  if (run == 1) {
    pid_t pid = fork(); CHECK_ERR(pid);
    if (!pid) {
      int r = prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
      CHECK_ERR(r);
      r = sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpumask);
      CHECK_ERR(r);
      r = execvp(argv[start_arg], argv + start_arg);
      CHECK_ERR(r);
    }
    r = ts_wait(&t, pid, &ts); CHECK_ERR(r);
    r = wait_for_child(pid);
    pp_taskstats(&ts);
  }
  else {
    r = ts_wait(&t, waitpid, &ts); CHECK_ERR(r);
    pp_taskstats(&ts);
  }

  ts_finish(&t);
  return r;
}

