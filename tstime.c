/*
 * Copyright Georg Sauthoff 2009, GPLv2+
 */

#include "taskstat.h"
#include "tools.h"

#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>

#include <seccomp.h>

const char cg_memory_root[] = "/sys/fs/cgroup/memory/";

const char options[] = "+i:o:m:v:r:t:f:p:u:n:";
int infd;               // get seccomp whitelist
int outfd;              // print statistics
cpu_set_t cpumask;      // cpuset to run the command
char cpumask_str[200] = "";
rlim_t vs_lim;          // VSS limit, in bytes
long long rs_lim;       // RSS limit, in bytes
long long time_lim;     // time limit
rlim_t output_lim;      // output limit, in bytes
rlim_t proc_lim;        // process limit
uid_t uid;              // uid to run command
char cg_name[150] = ""; // name of cgroups

int pipes[2];           // sync between parent and init child
char cg_path[250];

int* seccomp_list;
int seccomp_list_size;
/* 21 60 231 0 1 2 3 8 4 5 292 12 21 9 11 10 158 228 59 35 -10058 15 */

int child_init(void* arg);
pid_t get_a_child(pid_t pid);
void cg_init();
void cg_addproc(pid_t pid);
void cg_destroy();

void input_ll(long long* val) {
  sscanf(optarg, "%lld", val);
  if (*val < -1) *val = -1;
}
void input_rlim(rlim_t* val) {
  long long tmp;
  sscanf(optarg, "%lld", &tmp);
  *val = tmp < 0 ? RLIM_INFINITY : tmp;
}

int main(int argc, char** argv)
{
  if (geteuid()) exit(1); // must run as root

  vs_lim = output_lim = proc_lim = RLIM_INFINITY;
  rs_lim = time_lim = -1; // default: no limit

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
      case 'v': input_rlim(&vs_lim); break;
      case 'r': input_ll(&rs_lim); break;
      case 't': input_ll(&time_lim); break;
      case 'f': input_rlim(&output_lim); break;
      case 'p': input_rlim(&proc_lim); break;
      case 'u': {
        long long val;
        input_ll(&val);
        if (val <= 0) exit(1); // not allow to run as root
        uid = val;
        break;
      }
      case 'n': strncpy(cg_name, optarg, sizeof(cg_name) - 1); break;
      case '?': exit(1);
    }
  }
  if (uid <= 0 || infd < 0 || outfd < 0) exit(1);

  if (!*cpumask_str) {
    gen_cpumask(cpumask_str, sizeof(cpumask_str));
    parse_cpumask(cpumask_str, &cpumask);
  }
  int start_arg = optind;

  if (rs_lim >= 0) cg_init();

  // get seccomp whitelist
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

  if (rs_lim >= 0) cg_addproc(init_pid);
  char buf[20] = " ";
  write(pipes[1], buf, 1); // process added to cgroups

  pid_t pid = get_a_child(init_pid);
  r = ts_wait(&t, pid, &ts); CHECK_ERR(r);
  write(pipes[1], buf, 1); // taskstats collection completed

  r = waitpid(init_pid, NULL, 0); CHECK_ERR(r);
  cg_destroy();

  print_taskstats(outfd, &ts);
  read(pipes[0], buf, 20);
  puts(buf);

  ts_finish(&t);
  return 0;
}

void command_run(char** argv)
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
  setrlimit(RLIMIT_STACK, &rlim); // no stack limit
  rlim.rlim_cur = rlim.rlim_max = proc_lim;
  setrlimit(RLIMIT_NPROC, &rlim);
  rlim.rlim_cur = rlim.rlim_max = output_lim;
  setrlimit(RLIMIT_FSIZE, &rlim);
  rlim.rlim_cur = rlim.rlim_max = vs_lim;
  setrlimit(RLIMIT_AS, &rlim);
  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &rlim); // not create core dump

  setgid(uid);
  setuid(uid); // drop root privileges

  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  for (int i = 0; i < seccomp_list_size; i++)
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_list[i], 0);
  seccomp_load(ctx);

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
  close(infd);
  close(outfd);

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

  char buf[20];
  read(pipes[0], buf, 1); // wait for cgroups adding

  char** argv = arg;
  pid_t pid = fork(); CHECK_ERR(pid);
  if (pid == 0) {
    close(pipes[0]);
    close(pipes[1]);
    command_run(argv);
  }
  else {
    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    if (time_lim >= 0) alarm(time_lim);

    sigset_t wait_mask; sigemptyset(&wait_mask);
    sigsuspend(&wait_mask);

    read(pipes[0], buf, 1); // wait for taskstats collecting
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

void cg_init()
{
  int len;
  while (1) {
    if (!*cg_name) {
      struct timeval now;
      gettimeofday(&now, NULL);
      len = sprintf(cg_path, "%scg_tstime_%ld%06d",
                    cg_memory_root, (long)now.tv_sec, (int)now.tv_usec);
    }
    else {
      len = sprintf(cg_path, "%scg_tstime_%s", cg_memory_root, cg_name);
    }
    if (mkdir(cg_path, 0755) < 0) {
      if (errno != EEXIST) exit(1);
      *cg_name = 0;
    }
    else break;
  }

  char buf[20];
  int wbytes = sprintf(buf, "%lld\n", rs_lim);
  strcpy(cg_path + len, "/memory.limit_in_bytes");
  int fd = open(cg_path, O_WRONLY | O_TRUNC);
  write(fd, buf, wbytes);
  close(fd);
  strcpy(cg_path + len, "/memory.memsw.limit_in_bytes");
  fd = open(cg_path, O_WRONLY | O_TRUNC);
  write(fd, buf, wbytes);
  close(fd);

  cg_path[len] = 0;
}

void cg_addproc(pid_t pid)
{
  char buf[20];
  int wbytes = sprintf(buf, "%d\n", (int)pid);
  int len = strlen(cg_path);
  strcpy(cg_path + len, "/tasks");

  int fd = open(cg_path, O_WRONLY | O_TRUNC);
  write(fd, buf, wbytes);
  close(fd);

  cg_path[len] = 0;
}

void cg_destroy()
{
  while (rmdir(cg_path) < 0);
}
