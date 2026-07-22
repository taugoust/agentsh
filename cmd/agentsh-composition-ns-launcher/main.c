#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BROKER_FD 3
#define INTERNAL_CHILD_ARG "--agentsh-composition-internal-child-v1"

static pid_t child_pid = -1;

static void fail(const char *operation) {
  fprintf(stderr, "agentsh-composition-ns-launcher: %s: %s\n", operation,
          strerror(errno));
  _exit(125);
}

static void forward_signal(int signal_number) {
  if (child_pid > 0)
    (void)kill(child_pid, signal_number);
}

static void receive_challenge(char nonce[33]) {
  char challenge[4096];
  ssize_t received = recv(BROKER_FD, challenge, sizeof(challenge) - 1, 0);
  if (received <= 0)
    fail("receive broker challenge");
  challenge[received] = '\0';
  if (strstr(challenge, "\"type\":\"challenge\"") == NULL) {
    errno = EPROTO;
    fail("validate broker challenge type");
  }
  const char *marker = "\"nonce\":\"";
  char *start = strstr(challenge, marker);
  if (!start) {
    errno = EPROTO;
    fail("locate broker challenge nonce");
  }
  start += strlen(marker);
  for (size_t index = 0; index < 32; index++) {
    if (!isxdigit((unsigned char)start[index])) {
      errno = EPROTO;
      fail("validate broker challenge nonce");
    }
    nonce[index] = start[index];
  }
  nonce[32] = '\0';
  if (start[32] != '"') {
    errno = EPROTO;
    fail("bound broker challenge nonce");
  }
}

static void send_map_request(uid_t uid, gid_t gid, const char *nonce) {
  char request[224];
  int length = snprintf(request, sizeof(request),
                        "{\"version\":1,\"type\":\"namespace-map\","
                        "\"uid\":%u,\"gid\":%u,\"nonce\":\"%s\"}",
                        (unsigned int)uid, (unsigned int)gid, nonce);
  if (length <= 0 || (size_t)length >= sizeof(request)) {
    errno = EOVERFLOW;
    fail("format namespace map request");
  }
  if (send(BROKER_FD, request, (size_t)length, MSG_NOSIGNAL) != length)
    fail("send namespace map request");

  char response[4096];
  ssize_t received = recv(BROKER_FD, response, sizeof(response) - 1, 0);
  if (received <= 0)
    fail("receive namespace map response");
  response[received] = '\0';
  if (strstr(response, "\"ok\":true") == NULL) {
    fprintf(stderr,
            "agentsh-composition-ns-launcher: namespace map rejected: %s\n",
            response);
    _exit(125);
  }
}

static unsigned long parse_flags(const char *value) {
  char *end = NULL;
  errno = 0;
  unsigned long result = strtoul(value, &end, 0);
  if (errno != 0 || end == value || *end != '\0') {
    errno = EINVAL;
    fail("parse namespace flags");
  }
  return result;
}

static unsigned int parse_id(const char *value) {
  char *end = NULL;
  errno = 0;
  unsigned long result = strtoul(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || result > 0xffffffffUL) {
    errno = EINVAL;
    fail("parse namespace identity");
  }
  return (unsigned int)result;
}

static void exec_internal_child(const char *adapter, bool new_session,
                                const char *nonce) {
  if (new_session && setsid() < 0)
    fail("create session");
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
    fail("set child parent-death signal");
  char *const child_argv[] = {(char *)adapter, (char *)INTERNAL_CHILD_ARG,
                              (char *)nonce, NULL};
  execv(adapter, child_argv);
  fail("exec adapter child");
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr,
            "usage: agentsh-composition-ns-launcher ADAPTER FLAGS NEW_SESSION "
            "UID GID\n");
    return 125;
  }
  const char *adapter = argv[1];
  unsigned long flags = parse_flags(argv[2]);
  bool new_session = strcmp(argv[3], "1") == 0;
  uid_t uid = (uid_t)parse_id(argv[4]);
  gid_t gid = (gid_t)parse_id(argv[5]);
  if (adapter[0] != '/' || uid != 1 || gid != 1) {
    errno = EINVAL;
    fail("validate launcher arguments");
  }
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
    fail("set launcher parent-death signal");

  unsigned long allowed_flags =
      CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP;
  if ((flags & ~allowed_flags) != 0 || (flags & CLONE_NEWNS) == 0) {
    errno = EINVAL;
    fail("validate namespace flags");
  }

  child_pid = (pid_t)syscall(SYS_clone, flags | CLONE_NEWUSER | SIGCHLD,
                             NULL, NULL, NULL, 0);
  if (child_pid < 0)
    fail("clone descendant namespaces");
  if (child_pid == 0) {
    child_pid = -1;
    char nonce[33];
    receive_challenge(nonce);
    send_map_request(uid, gid, nonce);
    exec_internal_child(adapter, new_session, nonce);
    return 125;
  }

  struct sigaction action = {.sa_handler = forward_signal};
  sigemptyset(&action.sa_mask);
  for (int signal_number = 1; signal_number < NSIG; signal_number++) {
    if (signal_number == SIGKILL || signal_number == SIGSTOP ||
        signal_number == SIGCHLD)
      continue;
    (void)sigaction(signal_number, &action, NULL);
  }
  int status = 0;
  while (waitpid(child_pid, &status, 0) < 0) {
    if (errno != EINTR)
      fail("wait for PID namespace init");
  }
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) {
    signal(WTERMSIG(status), SIG_DFL);
    raise(WTERMSIG(status));
  }
  return 125;
}
