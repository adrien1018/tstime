/*
 * Copyright Georg Sauthoff 2009, GPLv2+
 */

#include "taskstat.h"
#include "tools.h"

#include <time.h>
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

#include <getopt.h>
#include <seccomp.h>

const char cg_memory_root[] = "/sys/fs/cgroup/memory/";

const char optstring[] = "+u:o:m:v:r:t:f:p:n:s:c:h";
const struct option longopt[] = {
  {"uid",     1, NULL, 'u'},
  {"outfd",   1, NULL, 'o'},
  {"cpuset",  1, NULL, 'm'},
  {"vss",     1, NULL, 'v'},
  {"rss",     1, NULL, 'r'},
  {"time",    1, NULL, 't'},
  {"output",  1, NULL, 'f'},
  {"proc",    1, NULL, 'p'},
  {"name",    1, NULL, 'n'},
  {"syscall", 1, NULL, 's'},
  {"chroot",  1, NULL, 'c'},
  {"help"   , 0, NULL, 'h'}
};

uid_t uid;                  // uid to run command
int outfd;                  // print statistics
cpu_set_t cpumask;          // cpuset to run the command
char cpumask_str[200] = "";
rlim_t vs_lim;              // VSS limit (per proc), in bytes
long long rs_lim;           // RSS limit (total), in bytes
struct itimerval time_lim;  // time limit
rlim_t output_lim;          // output limit, in bytes
rlim_t proc_lim;            // process limit
char cg_name[150] = "";     // name of cgroups
char chroot_path[250] = ""; // path to chroot

int pipes[2];               // sync between parent and init child
char cg_path[250];

int* seccomp_list;
int seccomp_list_size;
/* 20:60,231,0,1,2,3,8,4,5,292,12,21,9,11,10,158,228,59,35,15
 * c: shared
 * 17:60,231,0,1,8,5,16,12,21,89,63,9,158,201,228,59,35
 * c: static
 * 56(clone) 2(open) 292(dup3)
 * --uid=1007 --time=5 --cpuset=2 --proc=1
 */

// --- cgroups ---

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
    if (mkdir(cg_path, 0755) < 0) { // create group
      if (errno != EEXIST) exit(1);
      *cg_name = 0; // if the name exists, use system time as name
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

  int fd = open(cg_path, O_WRONLY | O_APPEND);
  write(fd, buf, wbytes);
  close(fd);

  cg_path[len] = 0;
}

void cg_destroy()
{
  struct timespec tenth = {
    .tv_sec = 0,
    .tv_nsec = 100000000l
  };
  for (int i = 0; i < 10; i++) {
    if (rmdir(cg_path) == 0) return;
    nanosleep(&tenth, NULL); // try again
  }
  exit(1); // failed to remove cgroups
}

// --- execution ---

void command_run(char** argv)
{
  int r;
  r = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  CHECK_ERR(r);
  r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  CHECK_ERR(r);
  r = sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpumask);
  CHECK_ERR(r);

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

  if (*chroot_path) {
    r = chroot(chroot_path);
    CHECK_ERR(r);
    r = chdir("/");
    CHECK_ERR(r);
  }

  setgid(uid);
  setuid(uid); // drop root privileges

  if (seccomp_list_size != -1) {
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);
    for (int i = 0; i < seccomp_list_size; i++)
      seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_list[i], 0);
    seccomp_load(ctx);
  }

  r = execvp(argv[0], argv);
  CHECK_ERR(r);
}

void sig_handler(int signo)
{
  if (signo == SIGALRM) {
    _exit(0); // this will kill all children because of namespace
  }
}

int child_init(void* arg)
{
  prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

  close(outfd);

  struct sigaction act;
  act.sa_handler = sig_handler;
  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGCHLD);
  sigaddset(&act.sa_mask, SIGALRM);
  sigaction(SIGCHLD, &act, NULL);
  sigaction(SIGALRM, &act, NULL);
  sigprocmask(SIG_SETMASK, &act.sa_mask, NULL);

  char buf[20];
  read(pipes[0], buf, 1); // wait for cgroups adding
  if (!time_lim.it_interval.tv_sec) // start time limit
    setitimer(ITIMER_REAL, &time_lim, NULL);

  pid_t pid = fork(); CHECK_ERR(pid);
  if (pid == 0) {
    close(pipes[0]);
    close(pipes[1]);
    command_run((char**) arg);
  }
  else {
    sigset_t wait_mask; sigemptyset(&wait_mask);
    sigsuspend(&wait_mask);
    wait(NULL);
  }
  return 0;
}

// --- parsing ---

void input_ll(long long* val) {
  sscanf(optarg, "%lld", val);
  if (*val < -1) *val = -1;
}

void input_rlim(rlim_t* val) {
  long long tmp;
  sscanf(optarg, "%lld", &tmp);
  *val = tmp < 0 ? RLIM_INFINITY : tmp;
}

void display_help()
{
  fprintf(stderr,
          "Usage: ./tstime UID [options] command [args...]\n\n"
          "Options:\n"
          "  -o FD, --output=FD\t\tOutput statistics to file descriptor FD\n"
          "  -m CPUS, --cpuset=CPUS\tSet CPU affinity (in list format)\n"
          "  -v SIZE, --vss=SIZE\t\tLimit VSS usage to SIZE bytes per process\n"
          "  -r SIZE, --rss=SIZE\t\tLimit RSS usage to SIZE bytes in total\n"
          "  -t TIME, --time=TIME\t\tLimit running time to TIME microseconds\n"
          "  -f SIZE, --output=SIZE\tSet file size limit to SIZE bytes\n"
          "  -p NUM, --proc=NUM\t\tLimit the total process number of the user\n"
          "  -n STR, --name=STR\t\tSet the default name of created cgroup\n"
          "\t\t\t\t to \'cg_tstime_STR\'\n"
          "  -s LIST, --syscall=LIST\tBlock all system calls except LIST, format:\n"
          "\t\t\t\t [# syscalls]:[syscall nums (comma delim)]\n"
          "  -c ROOT, --chroot=ROOT\tRun command by chroot ROOT\n"
          "\t\t\t\t (thus the executable path is relative to ROOT)\n");
}

void parse_args(int argc, char** argv)
{
  if (argc < 3) {
    display_help();
    exit(1);
  }

  int ret;
  sscanf(argv[1], "%d", &ret);
  if (ret <= 0) {
    fprintf(stderr, "Invalid UID %s.\n", argv[1]);
    exit(1); // not allow to run command as root
  }
  uid = ret;

  opterr = 0; optind = 2;
  while ((ret = getopt_long(argc, argv, optstring, longopt, NULL)) != -1) {
    switch (ret) {
      case 'o': sscanf(optarg, "%d", &outfd); break;
      case 'm': {
        if (parse_cpumask(optarg, &cpumask) < 0) exit(1);
        strcpy(cpumask_str, optarg);
        break;
      }
      case 'v': input_rlim(&vs_lim); break;
      case 'r': input_ll(&rs_lim); break;
      case 't': {
        long long val;
        input_ll(&val);
        if (val > 0) {
          time_lim = (struct itimerval)
            {{0, 0}, {val / 1000000, val % 1000000}};
        }
        break;
      }
      case 'f': input_rlim(&output_lim); break;
      case 'p': input_rlim(&proc_lim); break;
      case 'u': sscanf(optarg, "%d", &ret); uid = ret; break;
      case 'n': strncpy(cg_name, optarg, sizeof(cg_name) - 1); break;
      case 's': {
        int offset = 0, chars;
        sscanf(optarg, "%d%*c%n", &seccomp_list_size, &offset);
        if (seccomp_list_size < 0) exit(1);

        seccomp_list = (int*) malloc(seccomp_list_size * sizeof(int));
        for (int i = 0; i < seccomp_list_size; i++) {
          sscanf(optarg + offset, "%d%*c%n", seccomp_list + i, &chars);
          offset += chars;
        }
        break;
      }
      case 'c': strncpy(chroot_path, optarg, sizeof(chroot_path) - 1); break;
      case 'h': display_help(); exit(0);
      case '?': display_help(); exit(1);
    }
  }
  if (uid <= 0 || outfd < 0) exit(1);
}

int main(int argc, char** argv)
{
  if (geteuid()) {
    fprintf(stderr, "Must run by root.\n");
    exit(1);
  }
  // default: no limits
  vs_lim = output_lim = proc_lim = RLIM_INFINITY;
  rs_lim = time_lim.it_interval.tv_sec = -1;
  seccomp_list_size = -1;

  parse_args(argc, argv);
  int start_arg = optind;

  if (rs_lim >= 0) cg_init();
  if (!*cpumask_str) {
    gen_cpumask(cpumask_str, sizeof(cpumask_str));
    parse_cpumask(cpumask_str, &cpumask);
  }

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
  char tmpchar = ' ';
  write(pipes[1], &tmpchar, 1); // process added to cgroups

  r = ts_wait(&t, init_pid, &ts); CHECK_ERR(r);
  print_taskstats(outfd, &ts);

  r = waitpid(init_pid, NULL, 0); CHECK_ERR(r);
  if (rs_lim >= 0) cg_destroy();
  ts_finish(&t);
  return 0;
}
