#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_statmount
#define SYS_statmount 457
#endif
#ifndef SYS_listmount
#define SYS_listmount 458
#endif

#define INSPECT_MAX_MOUNTS 4096
#define INSPECT_BATCH 256
#define INSPECT_BUFFER 8192

static bool path_within(const char *path, const char *root);

static void fail(const char *op) {
  fprintf(stderr, "agentsh-composition-mount-helper: %s: %s\n", op,
          strerror(errno));
  _exit(125);
}

static void mkdir_parents(const char *path) {
  if (!path || path[0] != '/' || strlen(path) >= PATH_MAX) {
    errno = EINVAL;
    fail("invalid absolute path");
  }
  char copy[PATH_MAX];
  strcpy(copy, path);
  for (char *p = copy + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    struct stat st;
    if (lstat(copy, &st) == 0) {
      if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        fail("non-directory path component");
      }
    } else if (errno == ENOENT) {
      if (mkdir(copy, 0755) != 0 && errno != EEXIST)
        fail("mkdir parent");
    } else {
      fail("lstat parent");
    }
    *p = '/';
  }
}

static void ensure_dir(const char *path) {
  mkdir_parents(path);
  struct stat st;
  if (lstat(path, &st) == 0) {
    if (!S_ISDIR(st.st_mode)) {
      errno = ENOTDIR;
      fail("directory target exists as non-directory");
    }
    return;
  }
  if (errno != ENOENT || mkdir(path, 0755) != 0)
    fail("mkdir target");
}

static void ensure_file(const char *path) {
  mkdir_parents(path);
  struct stat st;
  if (lstat(path, &st) == 0) {
    if (!S_ISREG(st.st_mode)) {
      errno = EINVAL;
      fail("file target exists as non-file");
    }
    return;
  }
  if (errno != ENOENT)
    fail("lstat file target");
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  if (fd < 0)
    fail("create file target");
  close(fd);
}

static __u64 bind_attributes(const char *arg) {
  __u64 attributes = 0;
  if (strstr(arg, "ro"))
    attributes |= MOUNT_ATTR_RDONLY;
  if (strstr(arg, "nosuid"))
    attributes |= MOUNT_ATTR_NOSUID;
  if (strstr(arg, "nodev"))
    attributes |= MOUNT_ATTR_NODEV;
  if (strstr(arg, "noexec"))
    attributes |= MOUNT_ATTR_NOEXEC;
  if (strstr(arg, "nosymfollow"))
    attributes |= MOUNT_ATTR_NOSYMFOLLOW;
  return attributes;
}

static void clone_mount_fd(const char *target, const char *argument) {
  int tree_fd;
  if (strstr(argument, "detached")) {
    tree_fd = fcntl(6, F_DUPFD_CLOEXEC, 7);
    if (tree_fd < 0)
      fail("duplicate detached bind source tree");
  } else {
    unsigned int clone_flags =
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH;
    if (strstr(argument, "recursive"))
      clone_flags |= AT_RECURSIVE;
    tree_fd = syscall(SYS_open_tree, 6, "", clone_flags);
    if (tree_fd < 0)
      fail("clone bind source tree");
  }

  struct mount_attr attributes = {
      .attr_set = bind_attributes(argument),
  };
  if (syscall(SYS_mount_setattr, tree_fd, "", AT_EMPTY_PATH | AT_RECURSIVE,
              &attributes, sizeof(attributes)) != 0) {
    int saved = errno;
    close(tree_fd);
    errno = saved;
    fail("apply cloned mount attributes");
  }
  if (syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, target,
              MOVE_MOUNT_F_EMPTY_PATH) != 0) {
    int saved = errno;
    close(tree_fd);
    errno = saved;
    fail("attach cloned mount tree");
  }
  close(tree_fd);
}

static void mount_private_proc(const char *target, const char *argument) {
  if (argument[0] != '\0' && strcmp(argument, "hidepid=0") != 0) {
    errno = EINVAL;
    fail("validate proc mount options");
  }
  ensure_dir(target);
  int filesystem = syscall(SYS_fsopen, "proc", FSOPEN_CLOEXEC);
  if (filesystem < 0)
    fail("fsopen proc");
  if (argument[0] != '\0' &&
      syscall(SYS_fsconfig, filesystem, FSCONFIG_SET_STRING, "hidepid", "0",
              0) != 0) {
    int saved = errno;
    close(filesystem);
    errno = saved;
    fail("configure proc hidepid");
  }
  if (syscall(SYS_fsconfig, filesystem, FSCONFIG_CMD_CREATE, NULL, NULL, 0) !=
      0) {
    int saved = errno;
    close(filesystem);
    errno = saved;
    fail("create proc filesystem");
  }
  int mount_fd = syscall(SYS_fsmount, filesystem, FSMOUNT_CLOEXEC,
                         MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                             MOUNT_ATTR_NOEXEC);
  if (mount_fd < 0) {
    int saved = errno;
    close(filesystem);
    errno = saved;
    fail("fsmount proc");
  }
  close(filesystem);
  if (syscall(SYS_move_mount, mount_fd, "", AT_FDCWD, target,
              MOVE_MOUNT_F_EMPTY_PATH) != 0) {
    int saved = errno;
    close(mount_fd);
    errno = saved;
    fail("attach proc mount");
  }
  close(mount_fd);
}

static void write_proc_value_at(int process_fd, const char *name,
                                const char *value, bool optional) {
  int fd = openat(process_fd, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    if (optional && errno == ENOENT)
      return;
    fail("open pinned namespace mapping file");
  }
  size_t length = strlen(value);
  if (write(fd, value, length) != (ssize_t)length) {
    int saved = errno;
    close(fd);
    errno = saved;
    fail("write pinned namespace mapping file");
  }
  if (close(fd) != 0)
    fail("close pinned namespace mapping file");
}

static void map_namespace_ids(const char *target, const char *argument) {
  char *end = NULL;
  errno = 0;
  long pid = strtol(target, &end, 10);
  if (errno != 0 || end == target || *end != '\0' || pid <= 0 ||
      strcmp(argument, "1:1") != 0) {
    errno = EINVAL;
    fail("validate namespace mapping request");
  }
  if (setns(3, CLONE_NEWUSER) != 0)
    fail("setns mapping parent user namespace");

  /* fd 4 is a descriptor for the exact /proc/PID task directory pinned by
     the broker before it authenticated the launcher. Never reopen a numeric
     /proc path here: PID reuse between validation and map writes could grant a
     substituted process a namespace mapping. */
  write_proc_value_at(4, "uid_map", "1 1 1\n", false);
  write_proc_value_at(4, "setgroups", "deny\n", true);
  write_proc_value_at(4, "gid_map", "1 1 1\n", false);
}

static bool path_within(const char *path, const char *root) {
  size_t root_length = strlen(root);
  if (strcmp(path, root) == 0)
    return true;
  if (root_length == 1 && root[0] == '/')
    return path[0] == '/';
  return strncmp(path, root, root_length) == 0 && path[root_length] == '/';
}

static void print_mount_record(char kind, unsigned long long mount_id,
                               unsigned long long attributes,
                               const char *filesystem, const char *path) {
  if (!filesystem || !path || strchr(filesystem, '\t') ||
      strchr(filesystem, '\n') || strchr(path, '\t') || strchr(path, '\n')) {
    errno = EINVAL;
    fail("encode mount inventory");
  }
  if (dprintf(STDOUT_FILENO, "%c\t%llu\t%llu\t%s\t%s\n", kind,
              mount_id, attributes, filesystem, path) < 0)
    fail("write mount inventory");
}

static void stat_mount_record(unsigned long long mount_id, char kind,
                              const char *source_path, bool filter_path) {
  char storage[INSPECT_BUFFER] = {0};
  struct statmount *status = (struct statmount *)storage;
  struct mnt_id_req request = {
      .size = sizeof(request),
      .mnt_ns_fd = 0,
      .mnt_id = mount_id,
      .param = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE,
      .mnt_ns_id = 0,
  };
  if (syscall(SYS_statmount, &request, status, sizeof(storage), 0) != 0)
    fail("statmount source tree");
  if ((status->mask & (STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT |
                       STATMOUNT_FS_TYPE)) !=
      (STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT | STATMOUNT_FS_TYPE)) {
    errno = ENOTSUP;
    fail("incomplete statmount source tree");
  }
  size_t string_base = offsetof(struct statmount, str);
  if (status->size < string_base || status->size > sizeof(storage) ||
      status->mnt_point >= status->size - string_base ||
      status->fs_type >= status->size - string_base) {
    errno = EOVERFLOW;
    fail("bound statmount strings");
  }
  const char *point = status->str + status->mnt_point;
  const char *filesystem = status->str + status->fs_type;
  size_t remaining_point = status->size - string_base - status->mnt_point;
  size_t remaining_type = status->size - string_base - status->fs_type;
  if (!memchr(point, '\0', remaining_point) ||
      !memchr(filesystem, '\0', remaining_type)) {
    errno = EOVERFLOW;
    fail("terminate statmount strings");
  }
  if (filter_path && !path_within(point, source_path))
    return;
  if (kind == 'M') {
    /* listmount() includes covered members of a mount stack. Only the top
       member is reachable by pathname and can affect the sandbox view. Keep
       the visible graph deterministic while retaining duplicate-path
       rejection in the broker for malformed helper output. */
    struct statx visible = {0};
    if (syscall(SYS_statx, AT_FDCWD, point, AT_STATX_SYNC_AS_STAT,
                STATX_MNT_ID_UNIQUE, &visible) != 0)
      fail("resolve visible source mount");
    if ((visible.stx_mask & STATX_MNT_ID_UNIQUE) == 0) {
      errno = ENOTSUP;
      fail("identify visible source mount");
    }
    if (visible.stx_mnt_id != mount_id)
      return;
  }
  print_mount_record(kind, mount_id, status->mnt_attr, filesystem,
                     kind == 'S' ? source_path : point);
}

static void inspect_mount_tree(const char *source_path,
                               unsigned long long root_id) {
  stat_mount_record(root_id, 'S', source_path, false);

  struct mnt_id_req request = {
      .size = sizeof(request),
      .mnt_ns_fd = 0,
      .mnt_id = root_id,
      .param = 0,
      .mnt_ns_id = 0,
  };
  unsigned long long ids[INSPECT_BATCH];
  size_t total = 0;
  for (;;) {
    ssize_t count = syscall(SYS_listmount, &request, ids, INSPECT_BATCH, 0);
    if (count < 0)
      fail("listmount source tree");
    for (ssize_t index = 0; index < count; index++)
      stat_mount_record(ids[index], 'M', source_path, true);
    total += (size_t)count;
    if (total > INSPECT_MAX_MOUNTS) {
      errno = E2BIG;
      fail("bound source mount inventory");
    }
    if (count < INSPECT_BATCH)
      break;
    request.param = ids[count - 1];
  }
}

static void print_hex_path(const char *path) {
  static const char digits[] = "0123456789abcdef";
  for (const unsigned char *cursor = (const unsigned char *)path; *cursor;
       cursor++) {
    char encoded[2] = {digits[*cursor >> 4], digits[*cursor & 0xf]};
    if (write(STDOUT_FILENO, encoded, sizeof(encoded)) !=
        (ssize_t)sizeof(encoded))
      fail("write inspected path");
  }
}

static void print_unresolved_path(const char *path, int error_number) {
  if (dprintf(STDOUT_FILENO, "M\t%d\t%zu\t", error_number, strlen(path)) < 0)
    fail("write unresolved path header");
  print_hex_path(path);
  if (write(STDOUT_FILENO, "\n", 1) != 1)
    fail("write unresolved path terminator");
}

/* Resolve every requested cwd component against the completed staged root.
   RESOLVE_IN_ROOT gives the same absolute-symlink semantics as the later
   pivot, while RESOLVE_NO_MAGICLINKS keeps proc-style magic links out of this
   identity check. The path itself came from the bounded normalized plan. */
static void inspect_completed_cwd(const char *root, const char *cwd) {
  if (!root || root[0] != '/' || !cwd || cwd[0] != '/' ||
      strlen(root) >= PATH_MAX || strlen(cwd) >= PATH_MAX) {
    errno = EINVAL;
    fail("validate completed cwd request");
  }
  int root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root_fd < 0)
    fail("open completed root");

  char relative[PATH_MAX];
  const char *without_root = cwd + 1;
  if (*without_root == '\0')
    strcpy(relative, ".");
  else
    strcpy(relative, without_root);

  size_t length = strlen(relative);
  int resolved_fd = -1;
  for (size_t index = 0; index <= length; index++) {
    if (index != length && relative[index] != '/')
      continue;
    char saved = relative[index];
    relative[index] = '\0';
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    resolved_fd = syscall(SYS_openat2, root_fd, relative, &how, sizeof(how));
    if (resolved_fd < 0) {
      int saved_errno = errno;
      char visible[PATH_MAX];
      if (snprintf(visible, sizeof(visible), "/%s", relative) < 0) {
        close(root_fd);
        fail("format unresolved cwd component");
      }
      print_unresolved_path(visible, saved_errno);
      close(root_fd);
      return;
    }
    close(resolved_fd);
    resolved_fd = -1;
    relative[index] = saved;
  }

  struct open_how final_how = {
      .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
      .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
  };
  resolved_fd = syscall(SYS_openat2, root_fd, relative, &final_how,
                        sizeof(final_how));
  if (resolved_fd < 0) {
    int saved_errno = errno;
    print_unresolved_path(cwd, saved_errno);
    close(root_fd);
    return;
  }
  struct stat status;
  if (fstat(resolved_fd, &status) != 0) {
    int saved_errno = errno;
    close(resolved_fd);
    close(root_fd);
    errno = saved_errno;
    fail("stat completed cwd");
  }
  if (dprintf(STDOUT_FILENO, "O\t%llu\t%llu\t%u\n",
              (unsigned long long)status.st_dev,
              (unsigned long long)status.st_ino,
              (unsigned int)status.st_mode) < 0) {
    close(resolved_fd);
    close(root_fd);
    fail("write completed cwd identity");
  }
  close(resolved_fd);
  close(root_fd);
}

static void inspect_source_tree(const char *source_path, bool descriptor) {
  if (!source_path || source_path[0] != '/' || strlen(source_path) >= PATH_MAX) {
    errno = EINVAL;
    fail("validate inspected source path");
  }
  struct statx status = {0};
  int directory_fd = descriptor ? 6 : AT_FDCWD;
  const char *path = descriptor ? "" : source_path;
  int flags = descriptor ? AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT
                         : AT_STATX_SYNC_AS_STAT;
  if (syscall(SYS_statx, directory_fd, path, flags, STATX_MNT_ID_UNIQUE,
              &status) != 0 ||
      (status.stx_mask & STATX_MNT_ID_UNIQUE) == 0) {
    errno = ENOTSUP;
    fail("statx source mount identity");
  }
  inspect_mount_tree(source_path, status.stx_mnt_id);
}

static void do_operation(const char *operation, const char *target,
                         const char *argument) {
  if (strcmp(operation, "inspect-tree") == 0) {
    inspect_source_tree(target, true);
    return;
  }
  if (strcmp(operation, "inspect-path") == 0) {
    inspect_source_tree(target, false);
    return;
  }
  if (strcmp(operation, "inspect-cwd") == 0) {
    inspect_completed_cwd(target, argument);
    return;
  }
  if (strcmp(operation, "private") == 0) {
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
      fail("make propagation private");
    return;
  }
  if (strcmp(operation, "root") == 0) {
    ensure_dir(target);
    if (mount("tmpfs", target, "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=0755,size=512m") != 0)
      fail("mount root tmpfs");
    return;
  }
  if (strcmp(operation, "mkdir") == 0) {
    ensure_dir(target);
    return;
  }
  if (strcmp(operation, "hostname") == 0) {
    if (sethostname(target, strlen(target)) != 0)
      fail("sethostname");
    return;
  }
  if (strcmp(operation, "symlink") == 0) {
    mkdir_parents(target);
    if (symlink(argument, target) != 0)
      fail("symlink");
    return;
  }
  if (strcmp(operation, "tmpfs") == 0 ||
      strcmp(operation, "dev-root") == 0) {
    ensure_dir(target);
    unsigned long flags = MS_NOSUID;
    if (strcmp(operation, "tmpfs") == 0)
      flags |= MS_NODEV;
    if (mount("tmpfs", target, "tmpfs", flags,
              argument[0] ? argument : "size=256m") != 0)
      fail("mount tmpfs");
    return;
  }
  if (strcmp(operation, "proc") == 0) {
    mount_private_proc(target, argument);
    return;
  }
  if (strcmp(operation, "bind") == 0 ||
      strcmp(operation, "bind-device") == 0) {
    struct stat st;
    if (fstat(6, &st) != 0)
      fail("fstat bind source");
    if (S_ISDIR(st.st_mode))
      ensure_dir(target);
    else
      ensure_file(target);
    clone_mount_fd(target, argument);
    return;
  }
  if (strcmp(operation, "remount-ro") == 0) {
    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    if (syscall(SYS_mount_setattr, AT_FDCWD, target, 0, &attributes,
                sizeof(attributes)) != 0)
      fail("set read-only mount attributes");
    return;
  }
  if (strcmp(operation, "pivot") == 0) {
    if (chdir(target) != 0)
      fail("chdir staging root");
    if (mkdir(".oldroot", 0700) != 0)
      fail("mkdir old root");
    if (syscall(SYS_pivot_root, ".", ".oldroot") != 0)
      fail("pivot_root");
    if (chdir("/") != 0)
      fail("chdir new root");
    if (umount2("/.oldroot", MNT_DETACH) != 0)
      fail("detach old root");
    if (rmdir("/.oldroot") != 0)
      fail("remove old root");
    return;
  }
  errno = EINVAL;
  fail("unknown operation");
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "map-ids") == 0) {
    map_namespace_ids(argv[2], argv[3]);
    return 0;
  }
  if (argc != 5 || (strcmp(argv[4], "target") != 0 &&
                    strcmp(argv[4], "parent") != 0 &&
                    strcmp(argv[4], "owner") != 0)) {
    fprintf(stderr,
            "usage: agentsh-composition-mount-helper OP TARGET ARGUMENT "
            "PID_USER_MODE\n");
    return 125;
  }
  if (strcmp(argv[4], "owner") == 0) {
    /* Trusted mount construction stays in the PID namespace owner's user
       namespace. This avoids inheriting immutable mount locks when cloning
       parent-owned submounts into a less-privileged descendant user ns. */
    if (setns(7, CLONE_NEWUSER) != 0)
      fail("setns mount owner user");
    if (setns(4, CLONE_NEWPID) != 0)
      fail("setns pid");
  } else if (strcmp(argv[4], "parent") == 0) {
    /* A preserved PID namespace is owned by the adapter's parent user
       namespace. Enter that owner first to acquire the capability needed for
       setns(CLONE_NEWPID), then enter the requester's child user namespace. */
    if (setns(7, CLONE_NEWUSER) != 0)
      fail("setns pid owner user");
    if (setns(4, CLONE_NEWPID) != 0)
      fail("setns pid");
    /* Mounting procfs requires CAP_SYS_ADMIN in the user namespace that owns
       the selected PID namespace. Keep the narrowly invoked proc operation in
       that owner; all other operations shed back into the target user ns. */
    if (strcmp(argv[1], "proc") != 0 && setns(3, CLONE_NEWUSER) != 0)
      fail("setns user");
  } else {
    if (setns(3, CLONE_NEWUSER) != 0)
      fail("setns user");
    if (setns(4, CLONE_NEWPID) != 0)
      fail("setns pid");
  }
  if (setns(5, CLONE_NEWNS) != 0)
    fail("setns mount");

  pid_t child = fork();
  if (child < 0)
    fail("fork after pid setns");
  if (child == 0) {
    do_operation(argv[1], argv[2], argv[3]);
    _exit(0);
  }
  int status = 0;
  if (waitpid(child, &status, 0) < 0)
    fail("waitpid");
  if (!WIFEXITED(status))
    return 125;
  return WEXITSTATUS(status);
}
