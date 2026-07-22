#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/landlock.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <linux/stat.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define PATH_BUFFER 4096

static char test_root[PATH_BUFFER];

static void fatal(const char *operation) {
  fprintf(stderr, "landlock-mount-graph-probe: %s: %s\n", operation,
          strerror(errno));
  exit(125);
}

static void fatal_message(const char *message) {
  fprintf(stderr, "landlock-mount-graph-probe: %s\n", message);
  exit(125);
}

static void make_path(char *buffer, size_t size, const char *suffix) {
  int written = snprintf(buffer, size, "%s/%s", test_root, suffix);
  if (written < 0 || (size_t)written >= size) {
    errno = ENAMETOOLONG;
    fatal("construct test path");
  }
}

static void mkdir_all(const char *path, mode_t mode) {
  char copy[PATH_BUFFER];
  size_t length = strlen(path);
  if (length == 0 || length >= sizeof(copy)) {
    errno = ENAMETOOLONG;
    fatal("mkdir path");
  }
  memcpy(copy, path, length + 1);
  for (char *cursor = copy + 1; *cursor != '\0'; cursor++) {
    if (*cursor != '/')
      continue;
    *cursor = '\0';
    if (mkdir(copy, mode) != 0 && errno != EEXIST)
      fatal("mkdir parent");
    *cursor = '/';
  }
  if (mkdir(copy, mode) != 0 && errno != EEXIST)
    fatal("mkdir leaf");
}

static void ensure_parent(const char *path) {
  char copy[PATH_BUFFER];
  size_t length = strlen(path);
  if (length == 0 || length >= sizeof(copy)) {
    errno = ENAMETOOLONG;
    fatal("parent path");
  }
  memcpy(copy, path, length + 1);
  char *slash = strrchr(copy, '/');
  if (slash == NULL || slash == copy)
    return;
  *slash = '\0';
  mkdir_all(copy, 0755);
}

static void write_text(const char *path, const char *contents) {
  ensure_parent(path);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0)
    fatal("create fixture file");
  size_t length = strlen(contents);
  ssize_t written = write(fd, contents, length);
  if (written < 0 || (size_t)written != length) {
    close(fd);
    fatal("write fixture file");
  }
  if (close(fd) != 0)
    fatal("close fixture file");
}

static void touch_file(const char *path) { write_text(path, ""); }

static void write_proc_file(const char *path, const char *contents) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    fatal(path);
  size_t length = strlen(contents);
  ssize_t written = write(fd, contents, length);
  if (written < 0 || (size_t)written != length) {
    close(fd);
    fatal(path);
  }
  if (close(fd) != 0)
    fatal(path);
}

static void enter_private_user_mount_namespace(void) {
  uid_t outer_uid = getuid();
  gid_t outer_gid = getgid();
  if (unshare(CLONE_NEWUSER) != 0)
    fatal("unshare user namespace");

  write_proc_file("/proc/self/setgroups", "deny\n");
  char mapping[128];
  int length = snprintf(mapping, sizeof(mapping), "0 %u 1\n", outer_uid);
  if (length < 0 || (size_t)length >= sizeof(mapping))
    fatal_message("format uid map");
  write_proc_file("/proc/self/uid_map", mapping);
  length = snprintf(mapping, sizeof(mapping), "0 %u 1\n", outer_gid);
  if (length < 0 || (size_t)length >= sizeof(mapping))
    fatal_message("format gid map");
  write_proc_file("/proc/self/gid_map", mapping);

  if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0)
    fatal("adopt namespace root identity");
  if (unshare(CLONE_NEWNS) != 0)
    fatal("unshare mount namespace");
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
    fatal("make mount propagation private");
}

static uint64_t handled_fs_rights(int abi) {
  uint64_t rights = LANDLOCK_ACCESS_FS_EXECUTE |
                    LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_READ_FILE |
                    LANDLOCK_ACCESS_FS_READ_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_CHAR |
                    LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2)
    rights |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3)
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  if (abi >= 5)
    rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  return rights;
}

static int landlock_abi(void) {
  int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                         LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0)
    fatal("query Landlock ABI");
  return abi;
}

static int create_ruleset(bool handle_ioctl) {
  int abi = landlock_abi();
  uint64_t rights = handled_fs_rights(abi);
  if (!handle_ioctl)
    rights &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
  struct landlock_ruleset_attr attr = {.handled_access_fs = rights};
  int fd = (int)syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
  if (fd < 0)
    fatal("create Landlock ruleset");
  return fd;
}

static void add_landlock_rule(int ruleset_fd, const char *path,
                              uint64_t rights) {
  int path_fd = open(path, O_PATH | O_CLOEXEC);
  if (path_fd < 0)
    fatal("open Landlock rule object");
  struct stat status;
  if (fstat(path_fd, &status) != 0) {
    close(path_fd);
    fatal("stat Landlock rule object");
  }
  if (!S_ISDIR(status.st_mode)) {
    rights &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
              LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
              LANDLOCK_ACCESS_FS_IOCTL_DEV;
  }
  struct landlock_path_beneath_attr attr = {
      .allowed_access = rights,
      .parent_fd = path_fd,
  };
  if (syscall(SYS_landlock_add_rule, ruleset_fd,
              LANDLOCK_RULE_PATH_BENEATH, &attr, 0) != 0) {
    close(path_fd);
    fatal("add Landlock path rule");
  }
  close(path_fd);
}

static void enforce_landlock(int ruleset_fd) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    fatal("set no_new_privs");
  if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0)
    fatal("restrict with Landlock");
  close(ruleset_fd);
}

static uint64_t read_rights(void) {
  return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
}

static uint64_t write_rights(int abi) {
  uint64_t rights = read_rights() | LANDLOCK_ACCESS_FS_WRITE_FILE |
                    LANDLOCK_ACCESS_FS_REMOVE_DIR |
                    LANDLOCK_ACCESS_FS_REMOVE_FILE |
                    LANDLOCK_ACCESS_FS_MAKE_DIR |
                    LANDLOCK_ACCESS_FS_MAKE_REG |
                    LANDLOCK_ACCESS_FS_MAKE_SOCK |
                    LANDLOCK_ACCESS_FS_MAKE_FIFO |
                    LANDLOCK_ACCESS_FS_MAKE_SYM;
  if (abi >= 2)
    rights |= LANDLOCK_ACCESS_FS_REFER;
  if (abi >= 3)
    rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
  return rights;
}

static int open_tree_clone_path(const char *source, bool recursive) {
  unsigned int flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
  if (recursive)
    flags |= AT_RECURSIVE;
  return (int)syscall(SYS_open_tree, AT_FDCWD, source, flags);
}

static int open_tree_clone_fd(int source_fd) {
  return (int)syscall(SYS_open_tree, source_fd, "",
                      OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH);
}

static int set_detached_attributes(int tree_fd, bool recursive,
                                   uint64_t attributes) {
  struct mount_attr attr = {
      .attr_set = attributes,
      .attr_clr = 0,
      .propagation = 0,
      .userns_fd = 0,
  };
  unsigned int flags = AT_EMPTY_PATH;
  if (recursive)
    flags |= AT_RECURSIVE;
  return (int)syscall(SYS_mount_setattr, tree_fd, "", flags, &attr,
                      sizeof(attr));
}

static int attach_tree(int tree_fd, const char *target) {
  return (int)syscall(SYS_move_mount, tree_fd, "", AT_FDCWD, target,
                      MOVE_MOUNT_F_EMPTY_PATH);
}

static int clone_attach(const char *source, const char *target, bool recursive,
                        uint64_t attributes) {
  int tree_fd = open_tree_clone_path(source, recursive);
  if (tree_fd < 0)
    return -1;
  if (attributes != 0 &&
      set_detached_attributes(tree_fd, recursive, attributes) != 0) {
    int saved = errno;
    close(tree_fd);
    errno = saved;
    return -1;
  }
  if (attach_tree(tree_fd, target) != 0) {
    int saved = errno;
    close(tree_fd);
    errno = saved;
    return -1;
  }
  return close(tree_fd);
}

static int read_file_result(const char *path, char *buffer, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -errno;
  ssize_t length = read(fd, buffer, size - 1);
  int saved = errno;
  close(fd);
  if (length < 0) {
    errno = saved;
    return -errno;
  }
  buffer[length] = '\0';
  return 0;
}

static bool expect_read(const char *path, const char *expected) {
  char buffer[256];
  int result = read_file_result(path, buffer, sizeof(buffer));
  if (result != 0) {
    fprintf(stderr, "expected read of %s, got %s\n", path,
            strerror(-result));
    return false;
  }
  if (strcmp(buffer, expected) != 0) {
    fprintf(stderr, "unexpected contents at %s: %s\n", path, buffer);
    return false;
  }
  return true;
}

static bool expect_denied(const char *path) {
  char buffer[16];
  int result = read_file_result(path, buffer, sizeof(buffer));
  if (result == -EACCES || result == -EPERM)
    return true;
  fprintf(stderr, "expected denial of %s, got %s\n", path,
          result == 0 ? "success" : strerror(-result));
  return false;
}

static bool expect_absent(const char *path) {
  char buffer[16];
  int result = read_file_result(path, buffer, sizeof(buffer));
  if (result == -ENOENT)
    return true;
  fprintf(stderr, "expected absence of %s, got %s\n", path,
          result == 0 ? "success" : strerror(-result));
  return false;
}

static uint64_t unique_mount_id(const char *path) {
  struct statx status = {0};
  if (syscall(SYS_statx, AT_FDCWD, path, AT_STATX_SYNC_AS_STAT,
              STATX_MNT_ID_UNIQUE, &status) != 0)
    return 0;
  if ((status.stx_mask & STATX_MNT_ID_UNIQUE) == 0)
    return 0;
  return status.stx_mnt_id;
}

static ssize_t list_mounts_below(uint64_t mount_id, uint64_t *ids,
                                 size_t count) {
  struct mnt_id_req request = {
      .size = sizeof(request),
      .mnt_ns_fd = 0,
      .mnt_id = mount_id,
      .param = 0,
      .mnt_ns_id = 0,
  };
  return syscall(SYS_listmount, &request, ids, count, 0);
}

static bool stat_mount_basic(uint64_t mount_id, struct statmount *status,
                             size_t size) {
  memset(status, 0, size);
  struct mnt_id_req request = {
      .size = sizeof(request),
      .mnt_ns_fd = 0,
      .mnt_id = mount_id,
      .param = STATMOUNT_MNT_BASIC | STATMOUNT_MNT_POINT |
               STATMOUNT_FS_TYPE,
      .mnt_ns_id = 0,
  };
  return syscall(SYS_statmount, &request, status, size, 0) == 0;
}

static bool verify_recursive_mount_inventory(const char *recursive_path,
                                             const char *shallow_path) {
  uint64_t recursive_id = unique_mount_id(recursive_path);
  uint64_t shallow_id = unique_mount_id(shallow_path);
  if (recursive_id == 0 || shallow_id == 0) {
    fprintf(stderr, "statx did not return unique mount IDs\n");
    return false;
  }
  uint64_t recursive_children[16] = {0};
  uint64_t shallow_children[16] = {0};
  ssize_t recursive_count =
      list_mounts_below(recursive_id, recursive_children,
                        ARRAY_LEN(recursive_children));
  ssize_t shallow_count = list_mounts_below(
      shallow_id, shallow_children, ARRAY_LEN(shallow_children));
  if (recursive_count < 1 || shallow_count != 0) {
    fprintf(stderr,
            "unexpected listmount result: recursive=%zd shallow=%zd\n",
            recursive_count, shallow_count);
    return false;
  }
  char storage[4096];
  bool found_tmpfs = false;
  for (ssize_t index = 0; index < recursive_count; index++) {
    struct statmount *status = (struct statmount *)storage;
    if (!stat_mount_basic(recursive_children[index], status,
                          sizeof(storage))) {
      fprintf(stderr, "statmount failed: %s\n", strerror(errno));
      return false;
    }
    if ((status->mask & STATMOUNT_FS_TYPE) != 0) {
      const char *type = status->str + status->fs_type;
      if (strcmp(type, "tmpfs") == 0) {
        uint64_t required = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                            MOUNT_ATTR_NOEXEC;
        if ((status->mnt_attr & required) != required) {
          fprintf(stderr, "recursive tmpfs lost restrictive attributes\n");
          return false;
        }
        found_tmpfs = true;
      }
    }
  }
  if (!found_tmpfs)
    fprintf(stderr, "recursive clone did not report its tmpfs mask\n");
  return found_tmpfs;
}

static void setup_common_root(void) {
  char template_path[] = "/tmp/agentsh-landlock-mount-graph-XXXXXX";
  char *created = mkdtemp(template_path);
  if (created == NULL)
    fatal("create test root");
  if (strlen(created) >= sizeof(test_root)) {
    errno = ENAMETOOLONG;
    fatal("store test root");
  }
  strcpy(test_root, created);
}

typedef void (*setup_fn)(void);
typedef void (*rules_fn)(int);
typedef bool (*broker_fn)(void);
typedef bool (*verify_fn)(void);

static int run_coordinated(const char *name, setup_fn setup, rules_fn rules,
                           broker_fn broker, verify_fn verify) {
  setup_common_root();
  enter_private_user_mount_namespace();
  setup();

  int ready_pipe[2];
  int done_pipe[2];
  if (pipe2(ready_pipe, O_CLOEXEC) != 0 || pipe2(done_pipe, O_CLOEXEC) != 0)
    fatal("create coordination pipes");

  pid_t child = fork();
  if (child < 0)
    fatal("fork Landlocked verifier");
  if (child == 0) {
    close(ready_pipe[0]);
    close(done_pipe[1]);
    int ruleset = create_ruleset(false);
    rules(ruleset);
    enforce_landlock(ruleset);
    char byte = 'R';
    if (write(ready_pipe[1], &byte, 1) != 1)
      _exit(120);
    if (read(done_pipe[0], &byte, 1) != 1 || byte != 'G')
      _exit(121);
    _exit(verify() ? 0 : 1);
  }

  close(ready_pipe[1]);
  close(done_pipe[0]);
  char byte = 0;
  if (read(ready_pipe[0], &byte, 1) != 1 || byte != 'R')
    fatal_message("Landlocked verifier did not become ready");
  bool broker_ok = broker();
  byte = broker_ok ? 'G' : 'E';
  if (write(done_pipe[1], &byte, 1) != 1)
    fatal("release verifier");
  close(ready_pipe[0]);
  close(done_pipe[1]);

  int status = 0;
  if (waitpid(child, &status, 0) < 0)
    fatal("wait for verifier");
  bool child_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (!broker_ok || !child_ok) {
    fprintf(stderr,
            "scenario %s failed: broker_ok=%d child_status=%d\n", name,
            broker_ok, status);
    return 1;
  }
  printf("scenario=%s result=pass\n", name);
  return 0;
}

static void setup_identity(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/tree/tagged/allowed");
  write_text(path, "allowed\n");
  make_path(path, sizeof(path), "original/tree/untagged/denied");
  write_text(path, "denied\n");
  make_path(path, sizeof(path), "stage/tree");
  mkdir_all(path, 0755);
}

static void rules_identity(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/tree/tagged");
  add_landlock_rule(ruleset, path, read_rights());
}

static bool broker_identity(void) {
  char source[PATH_BUFFER], target[PATH_BUFFER];
  make_path(source, sizeof(source), "original/tree");
  make_path(target, sizeof(target), "stage/tree");
  if (clone_attach(source, target, true,
                   MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                       MOUNT_ATTR_NOEXEC) != 0) {
    perror("identity recursive clone");
    return false;
  }
  return true;
}

static bool verify_identity(void) {
  char allowed[PATH_BUFFER], denied[PATH_BUFFER];
  make_path(allowed, sizeof(allowed), "stage/tree/tagged/allowed");
  make_path(denied, sizeof(denied), "stage/tree/untagged/denied");
  return expect_read(allowed, "allowed\n") && expect_denied(denied);
}

static void setup_nonidentity(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/etc/hosts");
  write_text(path, "hosts\n");
  make_path(path, sizeof(path), "original/etc/shadow");
  write_text(path, "shadow\n");
  make_path(path, sizeof(path), "stage/.host-etc");
  mkdir_all(path, 0755);
}

static void rules_nonidentity(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/etc/hosts");
  add_landlock_rule(ruleset, path, LANDLOCK_ACCESS_FS_READ_FILE);
}

static bool broker_nonidentity(void) {
  char source[PATH_BUFFER], target[PATH_BUFFER];
  make_path(source, sizeof(source), "original/etc");
  make_path(target, sizeof(target), "stage/.host-etc");
  if (clone_attach(source, target, true,
                   MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                       MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC) != 0) {
    perror("nonidentity recursive clone");
    return false;
  }
  return true;
}

static bool verify_nonidentity(void) {
  char allowed[PATH_BUFFER], denied[PATH_BUFFER];
  make_path(allowed, sizeof(allowed), "stage/.host-etc/hosts");
  make_path(denied, sizeof(denied), "stage/.host-etc/shadow");
  return expect_read(allowed, "hosts\n") && expect_denied(denied);
}

static void setup_descendant(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/store/package/marker");
  write_text(path, "store\n");
  make_path(path, sizeof(path), "stage/alias");
  mkdir_all(path, 0755);
}

static void rules_descendant(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/store");
  add_landlock_rule(ruleset, path, read_rights());
}

static bool broker_descendant(void) {
  char source[PATH_BUFFER], target[PATH_BUFFER];
  make_path(source, sizeof(source), "original/store/package");
  make_path(target, sizeof(target), "stage/alias");
  if (clone_attach(source, target, true,
                   MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                       MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC) != 0) {
    perror("descendant clone");
    return false;
  }
  return true;
}

static bool verify_descendant(void) {
  char original[PATH_BUFFER], alias[PATH_BUFFER];
  make_path(original, sizeof(original), "original/store/package/marker");
  make_path(alias, sizeof(alias), "stage/alias/marker");
  return expect_read(original, "store\n") && expect_denied(alias);
}

static void setup_destination_hazard(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/untagged/secret");
  write_text(path, "secret\n");
  make_path(path, sizeof(path), "stage/allowed/alias");
  mkdir_all(path, 0755);
}

static void rules_destination_hazard(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "stage/allowed");
  add_landlock_rule(ruleset, path, read_rights());
}

static bool broker_destination_hazard(void) {
  char source[PATH_BUFFER], target[PATH_BUFFER];
  make_path(source, sizeof(source), "original/untagged");
  make_path(target, sizeof(target), "stage/allowed/alias");
  if (clone_attach(source, target, true,
                   MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                       MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC) != 0) {
    perror("destination hazard clone");
    return false;
  }
  return true;
}

static bool verify_destination_hazard(void) {
  char original[PATH_BUFFER], alias[PATH_BUFFER];
  make_path(original, sizeof(original), "original/untagged/secret");
  make_path(alias, sizeof(alias), "stage/allowed/alias/secret");
  return expect_denied(original) && expect_read(alias, "secret\n");
}

static void setup_mask_preservation(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/run/control/secret");
  write_text(path, "underlying-secret\n");
  make_path(path, sizeof(path), "original/run/control");
  if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            "mode=0755,size=1m") != 0)
    fatal("mount control mask");
  make_path(path, sizeof(path), "original/run/control/visible");
  write_text(path, "masked-view\n");
  make_path(path, sizeof(path), "stage/recursive-run");
  mkdir_all(path, 0755);
  make_path(path, sizeof(path), "stage/shallow-run");
  mkdir_all(path, 0755);
}

static void rules_mask_preservation(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/run");
  add_landlock_rule(ruleset, path, read_rights());
}

static bool broker_mask_preservation(void) {
  char source[PATH_BUFFER], recursive[PATH_BUFFER], shallow[PATH_BUFFER];
  make_path(source, sizeof(source), "original/run");
  make_path(recursive, sizeof(recursive), "stage/recursive-run");
  make_path(shallow, sizeof(shallow), "stage/shallow-run");
  uint64_t attributes =
      MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
      MOUNT_ATTR_NOEXEC;
  if (clone_attach(source, recursive, true, attributes) != 0) {
    perror("recursive masked clone");
    return false;
  }
  if (clone_attach(source, shallow, false, attributes) != 0) {
    perror("shallow masked clone");
    return false;
  }
  return verify_recursive_mount_inventory(recursive, shallow);
}

static bool verify_mask_preservation(void) {
  char recursive_secret[PATH_BUFFER], recursive_visible[PATH_BUFFER];
  char shallow_secret[PATH_BUFFER];
  make_path(recursive_secret, sizeof(recursive_secret),
            "stage/recursive-run/control/secret");
  make_path(recursive_visible, sizeof(recursive_visible),
            "stage/recursive-run/control/visible");
  make_path(shallow_secret, sizeof(shallow_secret),
            "stage/shallow-run/control/secret");
  return expect_absent(recursive_secret) &&
         expect_read(recursive_visible, "masked-view\n") &&
         expect_read(shallow_secret, "underlying-secret\n");
}

static void setup_samepath_restore(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/nix/store/package/etc/rpc");
  write_text(path, "rpc-data\n");
  make_path(path, sizeof(path), "stage/nix");
  mkdir_all(path, 0755);
}

static void rules_samepath_restore(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "original/nix/store");
  add_landlock_rule(ruleset, path, read_rights());
}

static bool broker_samepath_restore(void) {
  char original_nix[PATH_BUFFER], stage_nix[PATH_BUFFER];
  char original_root[PATH_BUFFER], target_parent[PATH_BUFFER];
  char target[PATH_BUFFER];
  make_path(original_nix, sizeof(original_nix), "original/nix");
  make_path(stage_nix, sizeof(stage_nix), "stage/nix");
  make_path(original_root, sizeof(original_root), "original");
  make_path(target_parent, sizeof(target_parent),
            "stage/nix/store/package/etc");
  make_path(target, sizeof(target), "stage/nix/store/package/etc/rpc");

  if (clone_attach(original_nix, stage_nix, true,
                   MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                       MOUNT_ATTR_NOEXEC) != 0) {
    perror("clone identity /nix");
    return false;
  }
  if (mount("tmpfs", target_parent, "tmpfs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0755,size=1m") != 0) {
    perror("mount masked etc tmpfs");
    return false;
  }
  touch_file(target);

  int root_fd = open(original_root, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) {
    perror("open original root");
    return false;
  }
  struct open_how how = {
      .flags = O_PATH | O_CLOEXEC,
      .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
  };
  int source_fd = (int)syscall(
      SYS_openat2, root_fd, "nix/store/package/etc/rpc", &how, sizeof(how));
  close(root_fd);
  if (source_fd < 0) {
    perror("resolve original rpc");
    return false;
  }
  int tree_fd = open_tree_clone_fd(source_fd);
  close(source_fd);
  if (tree_fd < 0) {
    perror("clone original rpc file");
    return false;
  }
  if (set_detached_attributes(tree_fd, false,
                              MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                                  MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC) != 0) {
    perror("restrict rpc file mount");
    close(tree_fd);
    return false;
  }
  if (attach_tree(tree_fd, target) != 0) {
    perror("attach rpc file mount");
    close(tree_fd);
    return false;
  }
  close(tree_fd);
  return true;
}

static bool verify_samepath_restore(void) {
  char target[PATH_BUFFER];
  make_path(target, sizeof(target), "stage/nix/store/package/etc/rpc");
  if (!expect_read(target, "rpc-data\n"))
    return false;
  int fd = open(target, O_WRONLY | O_CLOEXEC);
  if (fd >= 0) {
    close(fd);
    fprintf(stderr, "same-path restored file unexpectedly writable\n");
    return false;
  }
  return errno == EACCES || errno == EPERM || errno == EROFS;
}

static void setup_destination_anchor(void) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "anchors/read-write");
  mkdir_all(path, 0755);
  // A rule on a directory hidden below a later fresh mount does not authorize
  // the fresh superblock. Provision and tag the actual synthetic filesystem
  // before Landlock enforcement; the broker later clones this mount root.
  if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            "mode=0755,size=1m") != 0)
    fatal("mount pre-enforcement synthetic tmpfs");
  make_path(path, sizeof(path), "stage/anchored-tmp");
  mkdir_all(path, 0755);
  make_path(path, sizeof(path), "stage/plain-tmp");
  mkdir_all(path, 0755);
}

static void rules_destination_anchor(int ruleset) {
  char path[PATH_BUFFER];
  make_path(path, sizeof(path), "anchors/read-write");
  add_landlock_rule(ruleset, path, write_rights(landlock_abi()));
}

static bool broker_destination_anchor(void) {
  char anchor[PATH_BUFFER], anchored[PATH_BUFFER], plain[PATH_BUFFER];
  make_path(anchor, sizeof(anchor), "anchors/read-write");
  make_path(anchored, sizeof(anchored), "stage/anchored-tmp");
  make_path(plain, sizeof(plain), "stage/plain-tmp");
  if (clone_attach(anchor, anchored, true,
                   MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV |
                       MOUNT_ATTR_NOEXEC) != 0) {
    perror("attach pre-tagged synthetic tmpfs");
    return false;
  }
  if (mount("tmpfs", plain, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            "mode=0755,size=1m") != 0) {
    perror("mount plain tmpfs");
    return false;
  }
  return true;
}

static bool verify_destination_anchor(void) {
  char anchored[PATH_BUFFER], plain[PATH_BUFFER];
  make_path(anchored, sizeof(anchored), "stage/anchored-tmp/created");
  make_path(plain, sizeof(plain), "stage/plain-tmp/created");
  int fd = open(anchored, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    fprintf(stderr, "anchored tmpfs create failed: %s\n", strerror(errno));
    return false;
  }
  if (write(fd, "anchor\n", 7) != 7) {
    close(fd);
    return false;
  }
  close(fd);
  fd = open(plain, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    close(fd);
    fprintf(stderr, "plain unanchored tmpfs unexpectedly writable\n");
    return false;
  }
  if (errno != EACCES && errno != EPERM)
    return false;
  return expect_read(anchored, "anchor\n");
}

static int run_ioctl_probe(bool allow_ioctl) {
  if (landlock_abi() < 5)
    fatal_message("Landlock ABI 5 is required for IOCTL_DEV probe");
  int ruleset = create_ruleset(true);
  uint64_t rights = LANDLOCK_ACCESS_FS_READ_FILE |
                    LANDLOCK_ACCESS_FS_WRITE_FILE;
  if (allow_ioctl)
    rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
  add_landlock_rule(ruleset, "/dev/null", rights);
  enforce_landlock(ruleset);

  int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    fatal("open /dev/null after Landlock");
  uint64_t size = 0;
  errno = 0;
  int result = ioctl(fd, BLKGETSIZE64, &size);
  int ioctl_errno = errno;
  close(fd);
  if (!allow_ioctl) {
    if (result == -1 && ioctl_errno == EACCES) {
      printf("scenario=ioctl-deny result=pass errno=EACCES\n");
      return 0;
    }
    fprintf(stderr, "expected IOCTL_DEV denial, got result=%d errno=%s\n",
            result, strerror(ioctl_errno));
    return 1;
  }
  if (result == -1 && ioctl_errno == EACCES) {
    fprintf(stderr, "IOCTL_DEV grant still returned EACCES\n");
    return 1;
  }
  printf("scenario=ioctl-allow result=pass driver_errno=%s\n",
         result == 0 ? "none" : strerror(ioctl_errno));
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: landlock-mount-graph-probe SCENARIO\n");
    return 125;
  }
  const char *scenario = argv[1];
  if (strcmp(scenario, "identity") == 0)
    return run_coordinated(scenario, setup_identity, rules_identity,
                           broker_identity, verify_identity);
  if (strcmp(scenario, "nonidentity") == 0)
    return run_coordinated(scenario, setup_nonidentity, rules_nonidentity,
                           broker_nonidentity, verify_nonidentity);
  if (strcmp(scenario, "descendant") == 0)
    return run_coordinated(scenario, setup_descendant, rules_descendant,
                           broker_descendant, verify_descendant);
  if (strcmp(scenario, "destination-hazard") == 0)
    return run_coordinated(scenario, setup_destination_hazard,
                           rules_destination_hazard,
                           broker_destination_hazard,
                           verify_destination_hazard);
  if (strcmp(scenario, "mask-preservation") == 0)
    return run_coordinated(scenario, setup_mask_preservation,
                           rules_mask_preservation,
                           broker_mask_preservation,
                           verify_mask_preservation);
  if (strcmp(scenario, "samepath-restore") == 0)
    return run_coordinated(scenario, setup_samepath_restore,
                           rules_samepath_restore, broker_samepath_restore,
                           verify_samepath_restore);
  if (strcmp(scenario, "synthetic-pool") == 0)
    return run_coordinated(scenario, setup_destination_anchor,
                           rules_destination_anchor,
                           broker_destination_anchor,
                           verify_destination_anchor);
  if (strcmp(scenario, "ioctl-deny") == 0)
    return run_ioctl_probe(false);
  if (strcmp(scenario, "ioctl-allow") == 0)
    return run_ioctl_probe(true);
  fprintf(stderr, "unknown scenario: %s\n", scenario);
  return 125;
}
