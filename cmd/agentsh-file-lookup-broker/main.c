// Linux-only, one-shot tracee-lineage lookup worker.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SYS_faccessat2
#define SYS_faccessat2 439
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_statx
#define SYS_statx 332
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef RESOLVE_NO_SYMLINKS
#define RESOLVE_NO_SYMLINKS 0x04
#endif
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif

#define CONTROL_FD 3
#define BASE_FD 4
#define PROTOCOL_VERSION 1U
#define REQUEST_MAGIC 0x51524c46U
#define RESULT_MAGIC 0x53524c46U
#define REQUEST_HEADER_SIZE 104U
#define RESULT_SIZE 32U
#define MAX_PATH_BYTES 4095U
#define MAX_LABEL_BYTES 4096U
#define MAX_PACKET_BYTES (128U + MAX_PATH_BYTES + MAX_LABEL_BYTES)

#define OP_OPEN 1U
#define OP_OPENAT2 2U
#define OP_STATX 3U
#define OP_FSTATAT 4U
#define OP_FACCESSAT 5U
#define OP_READLINK_METADATA 6U

#define CLASS_UNKNOWN 0U
#define CLASS_EXISTS 1U
#define CLASS_ABSENT 2U
#define CLASS_INACCESSIBLE 3U
#define CLASS_NOT_DIRECTORY 4U
#define CLASS_SYMLINK_LOOP 5U
#define CLASS_INVALID 6U

#define REASON_NONE 0U
#define REASON_PROTOCOL 5U
#define REASON_WORKER_UNAVAILABLE 7U
#define REASON_SECURITY_LABEL 14U
#define REASON_CONTEXT_UNAVAILABLE 16U
#define REASON_FUSE 18U
#define REASON_SYMLINK_CONTEXT 21U
#define REASON_ERRNO 22U

static uint16_t get_u16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static uint32_t get_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const unsigned char *p) {
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}
static void put_u16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
}
static void put_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}
static void put_u64(unsigned char *p, uint64_t v) {
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}

static void send_result(uint64_t id, uint16_t class_id, uint16_t reason,
                        int raw_errno) {
    unsigned char response[RESULT_SIZE];
    memset(response, 0, sizeof(response));
    put_u32(response, RESULT_MAGIC);
    put_u16(response + 4, PROTOCOL_VERSION);
    put_u16(response + 6, RESULT_SIZE);
    put_u64(response + 8, id);
    put_u16(response + 16, class_id);
    put_u16(response + 18, reason);
    put_u32(response + 20, raw_errno > 0 ? (uint32_t)raw_errno : 0U);
    (void)syscall(SYS_sendto, CONTROL_FD, response, sizeof(response),
                  MSG_NOSIGNAL, NULL, 0);
}

static int raw_close_range(unsigned int first, unsigned int last) {
#ifdef SYS_close_range
    return (int)syscall(SYS_close_range, first, last, 0U);
#else
    for (unsigned int fd = first; fd < 65536U && fd <= last; ++fd) {
        (void)syscall(SYS_close, fd);
    }
    return 0;
#endif
}

static int harden_worker(void) {
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) {
        return -1;
    }
    (void)prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[2];
    memset(&header, 0, sizeof(header));
    memset(data, 0, sizeof(data));
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    if (syscall(SYS_capset, &header, data) != 0 && errno != EPERM) {
        return -1;
    }
    // A non-privileged worker cannot remove inherited bounding bits. They are
    // inert because all current capability sets are empty, no_new_privs is
    // verified below, execve is absent from the seccomp allowlist, and this
    // worker never performs another exec. Drop every bit where the kernel
    // permits it and reject unexpected errors.
    for (unsigned int cap = 0; cap <= 63U; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0 &&
            errno != EINVAL && errno != EPERM) {
            return -1;
        }
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        return -1;
    }
    if (raw_close_range(5U, ~0U) != 0 && errno != ENOSYS) {
        return -1;
    }
    return 0;
}

#if defined(__x86_64__)
#define WORKER_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define WORKER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error unsupported lookup worker architecture
#endif

#define ALLOW_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install_worker_seccomp(void) {
    static struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WORKER_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        ALLOW_SYSCALL(SYS_read),
        ALLOW_SYSCALL(SYS_write),
        ALLOW_SYSCALL(SYS_close),
        ALLOW_SYSCALL(SYS_recvfrom),
        ALLOW_SYSCALL(SYS_sendto),
        ALLOW_SYSCALL(SYS_openat),
        ALLOW_SYSCALL(SYS_openat2),
        ALLOW_SYSCALL(SYS_newfstatat),
        ALLOW_SYSCALL(SYS_statx),
        ALLOW_SYSCALL(SYS_faccessat),
        ALLOW_SYSCALL(SYS_faccessat2),
        ALLOW_SYSCALL(SYS_fstatfs),
        ALLOW_SYSCALL(SYS_exit),
        ALLOW_SYSCALL(SYS_exit_group),
        ALLOW_SYSCALL(SYS_rt_sigreturn),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

static ssize_t read_current_label(char *buffer, size_t size) {
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/attr/current",
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = (ssize_t)syscall(SYS_read, fd, buffer, size);
    (void)syscall(SYS_close, fd);
    if (n <= 0 || (size_t)n >= size) {
        return -1;
    }
    while (n > 0 && (buffer[n - 1] == '\n' || buffer[n - 1] == '\0')) {
        --n;
    }
    return n;
}

static int fd_is_fuse(int fd) {
    struct statfs status;
    if (syscall(SYS_fstatfs, fd, &status) != 0) {
        return -1;
    }
    return (unsigned long)status.f_type == (unsigned long)FUSE_SUPER_MAGIC;
}

static int existing_ancestor_is_fuse(int base_fd, const char *path) {
    char parent[MAX_PATH_BYTES + 1U];
    size_t length = strnlen(path, MAX_PATH_BYTES + 1U);
    if (length == 0 || length > MAX_PATH_BYTES) {
        return -1;
    }
    memcpy(parent, path, length + 1U);
    while (1) {
        char *slash = strrchr(parent, '/');
        if (slash == NULL) {
            strcpy(parent, ".");
        } else if (slash == parent) {
            slash[1] = '\0';
        } else {
            *slash = '\0';
        }
        int fd = (int)syscall(SYS_openat, base_fd, parent,
                              O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd >= 0) {
            int fuse = fd_is_fuse(fd);
            (void)syscall(SYS_close, fd);
            return fuse;
        }
        if (errno != ENOENT && errno != ENOTDIR) {
            return -1;
        }
        if (strcmp(parent, ".") == 0 || strcmp(parent, "/") == 0) {
            return -1;
        }
    }
}

static int path_has_symlink(int base_fd, const char *path) {
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = O_PATH | O_CLOEXEC;
    how.resolve = RESOLVE_NO_SYMLINKS;
    int fd = (int)syscall(SYS_openat2, base_fd, path, &how, sizeof(how));
    if (fd >= 0) {
        (void)syscall(SYS_close, fd);
        return 0;
    }
    if (errno == ELOOP) {
        return 1;
    }
    if (errno == ENOENT || errno == ENOTDIR) {
        return 0;
    }
    // An unsupported diagnostic cannot securely attest the path topology.
    return -1;
}

static int perform_lookup(uint16_t operation, int base_fd, const char *path,
                          uint64_t open_flags, uint64_t resolve_flags,
                          uint32_t lookup_flags, uint32_t stat_mask,
                          uint32_t access_mode, uint32_t access_flags,
                          int *object_fd) {
    *object_fd = -1;
    switch (operation) {
    case OP_OPEN: {
        int flags;
        if ((open_flags & O_PATH) != 0) {
            flags = (int)(open_flags & (uint64_t)(O_PATH | O_DIRECTORY | O_NOFOLLOW));
            flags |= O_CLOEXEC;
        } else {
            flags = O_PATH | O_CLOEXEC;
            if ((open_flags & O_DIRECTORY) != 0) {
                flags |= O_DIRECTORY;
            }
        }
        int fd = (int)syscall(SYS_openat, base_fd, path, flags, 0);
        if (fd >= 0) {
            *object_fd = fd;
            return 0;
        }
        return errno;
    }
    case OP_OPENAT2: {
        struct open_how how;
        memset(&how, 0, sizeof(how));
        if ((open_flags & O_PATH) != 0) {
            how.flags = open_flags & (uint64_t)(O_PATH | O_DIRECTORY | O_NOFOLLOW);
            how.flags |= O_CLOEXEC;
        } else {
            how.flags = O_PATH | O_CLOEXEC;
            if ((open_flags & O_DIRECTORY) != 0) {
                how.flags |= O_DIRECTORY;
            }
        }
        how.resolve = resolve_flags;
        int fd = (int)syscall(SYS_openat2, base_fd, path, &how, sizeof(how));
        if (fd >= 0) {
            *object_fd = fd;
            return 0;
        }
        return errno;
    }
    case OP_STATX: {
        struct statx status;
        memset(&status, 0, sizeof(status));
        if (syscall(SYS_statx, base_fd, path, (int)lookup_flags,
                    stat_mask, &status) == 0) {
            return 0;
        }
        return errno;
    }
    case OP_FSTATAT: {
        struct stat status;
        memset(&status, 0, sizeof(status));
        if (syscall(SYS_newfstatat, base_fd, path, &status,
                    (int)lookup_flags) == 0) {
            return 0;
        }
        return errno;
    }
    case OP_FACCESSAT:
        if (syscall(SYS_faccessat2, base_fd, path, (int)access_mode,
                    (int)access_flags) == 0) {
            return 0;
        }
        return errno;
    case OP_READLINK_METADATA: {
        struct stat status;
        memset(&status, 0, sizeof(status));
        if (syscall(SYS_newfstatat, base_fd, path, &status,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            return 0;
        }
        return errno;
    }
    default:
        return EINVAL;
    }
}

int main(void) {
    char current_label[MAX_LABEL_BYTES + 1U];
    ssize_t current_label_len;
    if (harden_worker() != 0) {
        _exit(125);
    }
    current_label_len = read_current_label(current_label, sizeof(current_label));
    if (current_label_len < 0) {
        // The coordinator never advertises a production broker without an
        // attestable non-empty label. Retaining an empty sentinel here keeps
        // the native protocol independently testable on capability-only hosts.
        current_label_len = 0;
    }
    if (install_worker_seccomp() != 0) {
        _exit(125);
    }

    unsigned char packet[MAX_PACKET_BYTES];
    ssize_t received = (ssize_t)syscall(SYS_recvfrom, CONTROL_FD, packet,
                                        sizeof(packet), MSG_TRUNC, NULL, NULL);
    if (received < (ssize_t)REQUEST_HEADER_SIZE ||
        received > (ssize_t)sizeof(packet)) {
        send_result(1, CLASS_UNKNOWN, REASON_PROTOCOL, EPROTO);
        _exit(126);
    }
    uint64_t id = get_u64(packet + 8);
    uint32_t path_len = get_u32(packet + 88);
    uint32_t label_len = get_u32(packet + 92);
    if (get_u32(packet) != REQUEST_MAGIC ||
        get_u16(packet + 4) != PROTOCOL_VERSION ||
        get_u16(packet + 6) != REQUEST_HEADER_SIZE || id == 0 ||
        path_len == 0 || path_len > MAX_PATH_BYTES ||
        label_len > MAX_LABEL_BYTES ||
        REQUEST_HEADER_SIZE + path_len + label_len != (uint32_t)received ||
        memchr(packet + REQUEST_HEADER_SIZE, '\0', path_len) != NULL) {
        send_result(id == 0 ? 1 : id, CLASS_UNKNOWN, REASON_PROTOCOL, EPROTO);
        _exit(126);
    }
    const unsigned char *label = packet + REQUEST_HEADER_SIZE + path_len;
    if ((size_t)current_label_len != label_len ||
        memcmp(current_label, label, label_len) != 0) {
        send_result(id, CLASS_UNKNOWN, REASON_SECURITY_LABEL, 0);
        _exit(0);
    }

    char path[MAX_PATH_BYTES + 1U];
    memcpy(path, packet + REQUEST_HEADER_SIZE, path_len);
    path[path_len] = '\0';
    int base_fd = path[0] == '/' ? AT_FDCWD : BASE_FD;
    uint16_t operation = get_u16(packet + 32);
    uint64_t open_flags = get_u64(packet + 40);
    uint64_t resolve_flags = get_u64(packet + 56);
    uint32_t lookup_flags = get_u32(packet + 64);
    uint32_t stat_mask = get_u32(packet + 68);
    uint32_t access_mode = get_u32(packet + 72);
    uint32_t access_flags = get_u32(packet + 76);

    int object_fd = -1;
    int lookup_errno = perform_lookup(operation, base_fd, path, open_flags,
                                      resolve_flags, lookup_flags, stat_mask,
                                      access_mode, access_flags, &object_fd);
    if (lookup_errno == 0) {
        if (object_fd >= 0) {
            int fuse = fd_is_fuse(object_fd);
            (void)syscall(SYS_close, object_fd);
            if (fuse != 0) {
                send_result(id, CLASS_UNKNOWN,
                            fuse > 0 ? REASON_FUSE : REASON_CONTEXT_UNAVAILABLE,
                            0);
                _exit(0);
            }
        }
        send_result(id, CLASS_EXISTS, REASON_NONE, 0);
        _exit(0);
    }

    if (lookup_errno == ENOENT) {
        int symlink = path_has_symlink(base_fd, path);
        if (symlink != 0) {
            send_result(id, CLASS_UNKNOWN,
                        symlink > 0 ? REASON_SYMLINK_CONTEXT
                                    : REASON_CONTEXT_UNAVAILABLE,
                        lookup_errno);
            _exit(0);
        }
        int fuse = existing_ancestor_is_fuse(base_fd, path);
        if (fuse != 0) {
            send_result(id, CLASS_UNKNOWN,
                        fuse > 0 ? REASON_FUSE : REASON_CONTEXT_UNAVAILABLE,
                        lookup_errno);
            _exit(0);
        }
        send_result(id, CLASS_ABSENT, REASON_NONE, lookup_errno);
        _exit(0);
    }

    uint16_t class_id = CLASS_UNKNOWN;
    switch (lookup_errno) {
    case EACCES:
    case EPERM:
        class_id = CLASS_INACCESSIBLE;
        break;
    case ENOTDIR:
        class_id = CLASS_NOT_DIRECTORY;
        break;
    case ELOOP:
        class_id = CLASS_SYMLINK_LOOP;
        break;
    case EINVAL:
    case EBADF:
    case ESTALE:
        class_id = CLASS_INVALID;
        break;
    default:
        class_id = CLASS_UNKNOWN;
        break;
    }
    send_result(id, class_id, REASON_ERRNO, lookup_errno);
    _exit(0);
}
