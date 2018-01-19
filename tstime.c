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

const char options[] = "+i:o:m:v:t:f:p:u:";
// input fd, output fd, cpu mask, VSS limit,
// time limit, output limit, proc limits, user id

cpu_set_t cpumask;
char cpumask_str[200] = "";

int infd = STDIN_FILENO, outfd = STDOUT_FILENO, uid = 0;
unsigned int vs_lim = 65536, output_lim = 65536, time_lim = 2, proc_lim = 1;

int pipes[2];

int* seccomp_list;
int seccomp_list_size;
/* 21 60 231 0 1 2 3 8 4 5 292 12 21 9 11 10 158 228 59 35 -10058 15 */
int child_init(void* arg);
pid_t get_a_child(pid_t pid);

int main(int argc, char** argv)
{
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

  FILE* file = fdopen(infd, "r");
  if (!file) exit(1);
  fscanf(file, "%d", &seccomp_list_size);
  seccomp_list = (int*) malloc(seccomp_list_size * sizeof(int));
  for (int i = 0; i < seccomp_list_size; i++)
    fscanf(file, "%d", seccomp_list + i);

  int r = 0;

  struct ts_t t;
  r = ts_init(&t); CHECK_ERR_SIMPLE(r);

  r = ts_set_cpus(&t, cpumask_str); CHECK_ERR(r);

  struct taskstats ts;

  pipe(pipes);
  pid_t init_pid = clone(child_init, argv,
                         SIGCHLD | CLONE_NEWIPC | CLONE_NEWNET |
                         CLONE_NEWNS | CLONE_NEWPID,
                         argv + start_arg);

  pid_t pid = get_a_child(init_pid);
  r = ts_wait(&t, pid, &ts); CHECK_ERR(r);

  char buf[20] = " ";
  write(pipes[1], buf, 1);

  r = waitpid(init_pid, NULL, 0); CHECK_ERR(r);

  print_taskstats(outfd, &ts);
  read(pipes[0], buf, 20);
  puts(buf);

  ts_finish(&t);
  return 0;
}

void child_run(char** argv)
{
  int r;
  r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  CHECK_ERR(r);
  r = sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpumask);
  CHECK_ERR(r);
  //r = chroot("./");
  //CHECK_ERR(r);

  setreuid(uid, 0); // set real user id first to use RLIMIT_NPROC
  setregid(uid, 0);

  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
  setrlimit(RLIMIT_STACK, &rlim);
  rlim.rlim_cur = rlim.rlim_max = proc_lim;
  setrlimit(RLIMIT_NPROC, &rlim);
  rlim.rlim_cur = rlim.rlim_max = output_lim;
  setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = vs_lim << 10;
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim);

  setgid(uid);
  setuid(uid); // drop root privileges

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  for (int i = 0; i < seccomp_list_size; i++)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_list[i], 0);
  //seccomp_load(ctx);

  r = execvp(argv[0], argv);
  CHECK_ERR(r);
}

struct timeval end_time;

void sig_handler(int signo)
{
  if (signo == SIGCHLD) {
    gettimeofday(&end_time, NULL);
  }
  else {
    write(pipes[1], "HLE", 4);
    _exit(0); // this will kill child because of namespace
  }
}

int child_init(void* arg)
{
  struct sigaction act = {
    .sa_handler = sig_handler,
    .sa_flags = SA_RESTART
  };
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGCHLD);
  sigaddset(&act.sa_mask, SIGALRM);
  sigaction(SIGCHLD, &act, NULL);
  sigaction(SIGALRM, &act, NULL);
  sigprocmask(SIG_SETMASK, &act.sa_mask, NULL);

  char** argv = arg;
  pid_t pid = fork(); CHECK_ERR(pid);
  if (pid == 0) {
    close(pipes[0]);
    close(pipes[1]);
    close(infd);
    close(outfd);
    child_run(argv);
  }
  else {
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    alarm(time_lim);

    sigset_t wait_mask; sigemptyset(&wait_mask);
    sigsuspend(&wait_mask);

    char buf[20];
    read(pipes[0], buf, 1);
    wait(NULL);

    struct timeval duration;
    timersub(&end_time, &start_time, &duration);
    int bytes = sprintf(buf, "%lld", ((long long) duration.tv_sec) * 1000000
                         + duration.tv_usec);
    write(pipes[1], buf, bytes + 1);
  }
  return 0;
}

pid_t get_a_child(pid_t pid)
{
  int pipefd[2];
  pipe(pipefd);
  pid_t chpid = fork();
  if (chpid < 0) return chpid;
  if (chpid == 0) {
    char buf[15];
    sprintf(buf, "%d", (int)pid);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[0]); close(pipefd[1]);
    execlp("pgrep", "pgrep", "-P", buf);
    return -1;
  }

  waitpid(chpid, NULL, 0);
  int result;
  char buf[15];
  read(pipefd[0], buf, 15);
  close(pipefd[0]); close(pipefd[1]);
  if (sscanf(buf, "%d", &result) != 1) return -1;
  return (pid_t)result;
}
