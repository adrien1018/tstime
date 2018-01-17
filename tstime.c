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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>

#include <sched.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/genetlink.h>
#include <linux/taskstats.h>

#include <sys/prctl.h>
#include <seccomp.h>

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
  int code = 42;
  int status;
  pid_t r = waitpid(pid, &status, 0); CHECK_ERR(r);
  return code;
}

int main(int argc, char** argv)
{
  const char options[] = "+i:o:m:v:t:f:p:u:";
  // input fd, output fd, cpu mask, VSS limit,
  // time limit, output limit, proc limits, user id

  cpu_set_t cpumask;
  char cpumask_str[200] = "";

  int infd = 0, outfd = 1, uid = 0;
  unsigned int vs_lim = 65536, output_lim = 65536, time_lim = 2, proc_lim = 5;

  int ret;
  opterr = 0;
  while ((ret = getopt(argc, argv, options)) != -1) {
    switch (ret) {
      case 'i': sscanf(optarg, "%d", &infd); break;
      case 'o': sscanf(optarg, "%d", &outfd); break;
      case 'm': {
        if (parse_cpumask(optarg, &cpumask) < 0) exit(1);
        strcpy(cpumask_str, optarg);
        break;
      }
      case 'v': sscanf(optarg, "%u", &vs_lim); break;
      case 't': sscanf(optarg, "%u", &time_lim); break;
      case 'f': sscanf(optarg, "%u", &output_lim); break;
      case 'p': sscanf(optarg, "%u", &proc_lim); break;
      case 'u': sscanf(optarg, "%d", &uid); break;
      case '?': exit(1);
    }
  }
  if (uid <= 0) exit(1);
  if (!*cpumask_str) {
    gen_cpumask(cpumask_str, 200);
    parse_cpumask(cpumask_str, &cpumask);
  }
  int start_arg = optind;

  int* seccomp_list;
  int seccomp_list_size;
  FILE* file = fdopen(infd, "r");
  if (!file) exit(1);
  fscanf(file, "%d", &seccomp_list_size);
  seccomp_list = (int*) malloc(seccomp_list_size * sizeof(int));
  for (int i = 0; i < seccomp_list_size; i++)
    fscanf(file, "%d", seccomp_list + i);

  int r = 0;

  struct ts_t t;
  r = ts_init(&t); CHECK_ERR_SIMPLE(r);

  //install_chld_handler();
  r = ts_set_cpus(&t, cpumask_str); CHECK_ERR(r);

  struct taskstats ts;

  pid_t pid = fork(); CHECK_ERR(pid);
  if (!pid) {
    r = prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
    CHECK_ERR(r);
    r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    CHECK_ERR(r);
    r = sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpumask);
    CHECK_ERR(r);
    //r = close(infd);
    //CHECK_ERR(r);
    //r = close(outfd);
    //CHECK_ERR(r);
    //r = chroot("../");
    //CHECK_ERR(r);

    setreuid(uid, 0); // set real user id first to use RLIMIT_NPROC

    struct rlimit rlim;
    rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_STACK, &rlim);
    //rlim.rlim_cur = rlim.rlim_max = proc_lim;
    //setrlimit(RLIMIT_NPROC, &rlim);
    rlim.rlim_cur = rlim.rlim_max = output_lim;
    setrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = rlim.rlim_max = vs_lim << 10;
    setrlimit(RLIMIT_AS, &rlim);

    setuid(uid); // drop root privileges

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    for (int i = 0; i < seccomp_list_size; i++)
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_list[i], 0);
    seccomp_load(ctx);

    r = execvp(argv[start_arg], argv + start_arg);
    CHECK_ERR(r);
  }
  r = ts_wait(&t, pid, &ts); CHECK_ERR(r);
  r = wait_for_child(pid);

  print_taskstats(outfd, &ts);

  ts_finish(&t);
  exit(r);
}

