#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *op) {
  fprintf(stderr, "mount-broker-helper: %s: %s\n", op, strerror(errno));
  exit(125);
}

int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: mount-broker-helper SOURCE TARGET FSTYPE FLAGS DATA\n");
    return 125;
  }
  char *end = NULL;
  errno = 0;
  unsigned long flags = strtoul(argv[4], &end, 0);
  if (errno || end == argv[4] || *end) {
    fprintf(stderr, "mount-broker-helper: invalid flags: %s\n", argv[4]);
    return 125;
  }
  if (setns(3, CLONE_NEWUSER)) fail("setns user");
  if (setns(4, CLONE_NEWPID)) fail("setns pid");
  if (setns(5, CLONE_NEWNS)) fail("setns mount");

  pid_t child = fork();
  if (child < 0) fail("fork");
  if (child == 0) {
    const char *source = strcmp(argv[1], "-") ? argv[1] : NULL;
    const char *fstype = strcmp(argv[3], "-") ? argv[3] : NULL;
    const char *data = strcmp(argv[5], "-") ? argv[5] : NULL;
    if (mount(source, argv[2], fstype, flags, data)) fail("mount");
    _exit(0);
  }
  int status = 0;
  if (waitpid(child, &status, 0) < 0) fail("waitpid");
  if (!WIFEXITED(status)) return 125;
  return WEXITSTATUS(status);
}
