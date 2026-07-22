#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif
#ifndef SYS_statmount
#define SYS_statmount 457
#endif

#define BUFFER_SIZE 8192
#define PRESERVED_ATTRIBUTES                                                   \
  (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |                \
   MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSYMFOLLOW)

static void fatal(const char *operation) {
  fprintf(stderr, "recursive-mount-clone-probe: %s: %s\n", operation,
          strerror(errno));
  exit(1);
}

static uint64_t mount_attributes(const char *path) {
  struct statx st = {0};
  if (syscall(SYS_statx, AT_FDCWD, path, AT_STATX_SYNC_AS_STAT,
              STATX_MNT_ID_UNIQUE, &st) != 0)
    fatal("statx mount identity");
  if ((st.stx_mask & STATX_MNT_ID_UNIQUE) == 0) {
    errno = ENOTSUP;
    fatal("missing unique mount identity");
  }

  char storage[BUFFER_SIZE] = {0};
  struct statmount *status = (struct statmount *)storage;
  struct mnt_id_req request = {
      .size = sizeof(request),
      .mnt_id = st.stx_mnt_id,
      .param = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE,
  };
  if (syscall(SYS_statmount, &request, status, sizeof(storage), 0) != 0)
    fatal("statmount attributes");
  if ((status->mask & STATMOUNT_MNT_BASIC) == 0) {
    errno = ENOTSUP;
    fatal("missing mount attributes");
  }
  return status->mnt_attr & PRESERVED_ATTRIBUTES;
}

static void set_attributes(int mount_fd, unsigned int flags, uint64_t set,
                           uint64_t clear) {
  struct mount_attr attributes = {
      .attr_set = set,
      .attr_clr = clear,
  };
  if (syscall(SYS_mount_setattr, mount_fd, "", AT_EMPTY_PATH | flags,
              &attributes, sizeof(attributes)) != 0)
    fatal("mount_setattr detached tree");
}

static bool write_is_readonly(const char *path) {
  char test_path[4096];
  int length = snprintf(test_path, sizeof(test_path), "%s/agentsh-write-test",
                        path);
  if (length <= 0 || (size_t)length >= sizeof(test_path)) {
    errno = EOVERFLOW;
    fatal("format write test path");
  }
  int fd = open(test_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    close(fd);
    unlink(test_path);
    return false;
  }
  return errno == EROFS || errno == EACCES || errno == EPERM;
}

int main(int argc, char **argv) {
  if (argc != 5 ||
      (strcmp(argv[1], "baseline") != 0 && strcmp(argv[1], "union") != 0)) {
    fprintf(stderr,
            "usage: recursive-mount-clone-probe baseline|union SOURCE "
            "SOURCE_CHILD TARGET\n");
    return 2;
  }

  const char *mode = argv[1];
  const char *source = argv[2];
  const char *source_child = argv[3];
  const char *target = argv[4];
  if (source[0] != '/' || source_child[0] != '/' || target[0] != '/') {
    errno = EINVAL;
    fatal("validate paths");
  }
  struct stat target_status;
  if (lstat(target, &target_status) != 0 || !S_ISDIR(target_status.st_mode)) {
    errno = ENOTDIR;
    fatal("validate target directory");
  }
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    fatal("make propagation private");

  uint64_t source_root_attributes = mount_attributes(source);
  uint64_t source_child_attributes = mount_attributes(source_child);
  const uint64_t required = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;

  int tree_fd = syscall(SYS_open_tree, AT_FDCWD, source,
                        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE);
  if (tree_fd < 0)
    fatal("clone recursive tree");

  uint64_t recursive = required;
  if (strcmp(mode, "union") == 0)
    recursive |= source_root_attributes | source_child_attributes;
  set_attributes(tree_fd, AT_RECURSIVE, recursive, 0);
  if (strcmp(mode, "union") == 0) {
    uint64_t root_required = required | source_root_attributes;
    set_attributes(tree_fd, 0, root_required,
                   PRESERVED_ATTRIBUTES & ~root_required);
  }

  if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, target,
              MOVE_MOUNT_F_EMPTY_PATH) != 0)
    fatal("attach recursive tree");
  close(tree_fd);

  const char *relative = source_child + strlen(source);
  while (*relative == '/')
    relative++;
  char target_child[4096];
  int length = snprintf(target_child, sizeof(target_child), "%s/%s", target,
                        relative);
  if (length <= 0 || (size_t)length >= sizeof(target_child)) {
    errno = EOVERFLOW;
    fatal("format target child");
  }

  uint64_t target_root_attributes = mount_attributes(target);
  uint64_t target_child_attributes = mount_attributes(target_child);
  bool preserved =
      (target_child_attributes & source_child_attributes) ==
      source_child_attributes;
  bool readonly = write_is_readonly(target_child);
  printf("mode=%s source_root=%#llx source_child=%#llx target_root=%#llx "
         "target_child=%#llx preserved=%s readonly=%s\n",
         mode, (unsigned long long)source_root_attributes,
         (unsigned long long)source_child_attributes,
         (unsigned long long)target_root_attributes,
         (unsigned long long)target_child_attributes,
         preserved ? "true" : "false", readonly ? "true" : "false");

  if (strcmp(mode, "union") == 0 && (!preserved || !readonly))
    return 1;
  return 0;
}
