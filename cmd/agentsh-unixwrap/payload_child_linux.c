#define _GNU_SOURCE
#include "payload_child_linux.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOW(0, __u64)
#define SECCOMP_IOW(nr, type) _IOW('!', nr, type)
#define SECCOMP_IOCTL_NOTIF_ID_VALID SECCOMP_IOW(2, __u64)
#endif

#define LOCAL_MAGIC 0x484c5341U
#define LOCAL_VERSION 1U
#define LOCAL_PAYLOAD 2U
#define LOCAL_FRAME_SIZE 16U
#define LOCAL_FLAG_COMMAND_JAIL (1U << 0)
#define LOCAL_FLAG_FILE_LOOKUP (1U << 1)

#define CHILD_ATTEST_MAGIC 0x54544143U
#define CHILD_STATUS_MAGIC 0x53544143U
#define CHILD_MESSAGE_SIZE 32U

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

static int write_full(int fd, const void *buffer, size_t size) {
    const unsigned char *p = buffer;
    while (size > 0) {
        ssize_t n = (ssize_t)syscall(SYS_write, fd, p, size);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        p += (size_t)n;
        size -= (size_t)n;
    }
    return 0;
}

static int read_one(int fd, unsigned char *value) {
    while (1) {
        ssize_t n = (ssize_t)syscall(SYS_read, fd, value, 1U);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        return n == 1 ? 0 : -1;
    }
}

static void report_status(int fd, int status_errno) {
    unsigned char message[CHILD_MESSAGE_SIZE];
    memset(message, 0, sizeof(message));
    put_u32(message, CHILD_STATUS_MAGIC);
    put_u16(message + 4, LOCAL_VERSION);
    put_u16(message + 6, CHILD_MESSAGE_SIZE);
    put_u32(message + 8, status_errno > 0 ? (uint32_t)status_errno : 0U);
    (void)write_full(fd, message, sizeof(message));
}

static void child_fail(const struct agentsh_payload_spec *spec, int failure) {
    int saved = failure > 0 ? failure : (errno > 0 ? errno : EIO);
    report_status(spec->sync_child_fd, saved);
    _exit(127);
}

static int load_payload_filter(const unsigned char *bytes, size_t size,
                               int want_wait_killable) {
    if (bytes == NULL || size == 0 || size % sizeof(struct sock_filter) != 0 ||
        size / sizeof(struct sock_filter) > UINT16_MAX) {
        errno = EINVAL;
        return -1;
    }
    struct sock_fprog program;
    program.len = (unsigned short)(size / sizeof(struct sock_filter));
    program.filter = (struct sock_filter *)(uintptr_t)bytes;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    unsigned long flags = SECCOMP_FILTER_FLAG_NEW_LISTENER;
    if (want_wait_killable) {
        flags |= SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
    }
    int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &program);
    if (fd < 0 && errno == EINVAL && want_wait_killable) {
        flags &= ~SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;
        fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &program);
    }
    return fd;
}

static int probe_notify_fd(int fd) {
    uint64_t id = 0;
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0) {
        return 0;
    }
    return errno == ENOENT || errno == EINVAL ? 0 : -1;
}

static int send_payload_handoff(const struct agentsh_payload_spec *spec,
                                int notify_fd, int lookup_ready) {
    unsigned char frame[LOCAL_FRAME_SIZE];
    memset(frame, 0, sizeof(frame));
    put_u32(frame, LOCAL_MAGIC);
    put_u16(frame + 4, LOCAL_VERSION);
    put_u16(frame + 6, LOCAL_PAYLOAD);
    uint32_t flags = spec->command_jail ? LOCAL_FLAG_COMMAND_JAIL : 0U;
    if (lookup_ready) {
        flags |= LOCAL_FLAG_FILE_LOOKUP;
    }
    put_u32(frame + 8, flags);
    put_u32(frame + 12, LOCAL_FRAME_SIZE);

    int descriptors[2];
    descriptors[0] = notify_fd;
    size_t descriptor_count = 1;
    if (lookup_ready) {
        descriptors[descriptor_count++] = spec->broker_transfer_fd;
    }
    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(descriptors))];
    } control;
    memset(&control, 0, sizeof(control));
    struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = CMSG_SPACE(descriptor_count * sizeof(int));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(descriptor_count * sizeof(int));
    memcpy(CMSG_DATA(header), descriptors, descriptor_count * sizeof(int));
    ssize_t n = sendmsg(spec->control_fd, &message, MSG_NOSIGNAL);
    return n == (ssize_t)sizeof(frame) ? 0 : -1;
}

static void payload_child(const struct agentsh_payload_spec *spec) {
    (void)syscall(SYS_close, spec->sync_parent_fd);
    if (spec->broker_parent_fd >= 0) {
        (void)syscall(SYS_close, spec->broker_parent_fd);
    }

    sigset_t blocked;
    sigfillset(&blocked);
    (void)sigprocmask(SIG_SETMASK, &blocked, NULL);

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 ||
        (int)getppid() != spec->expected_parent_pid) {
        child_fail(spec, ESRCH);
    }
    int securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    int no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (securebits < 0 || no_new_privs < 0) {
        child_fail(spec, errno);
    }
    unsigned char attestation[CHILD_MESSAGE_SIZE];
    memset(attestation, 0, sizeof(attestation));
    put_u32(attestation, CHILD_ATTEST_MAGIC);
    put_u16(attestation + 4, LOCAL_VERSION);
    put_u16(attestation + 6, CHILD_MESSAGE_SIZE);
    put_u32(attestation + 8, (uint32_t)getpid());
    put_u32(attestation + 12, (uint32_t)syscall(SYS_gettid));
    put_u32(attestation + 16, (uint32_t)securebits);
    put_u32(attestation + 20, (uint32_t)no_new_privs);
    if (write_full(spec->sync_child_fd, attestation, sizeof(attestation)) != 0) {
        _exit(127);
    }

    unsigned char lookup_ready = 0;
    if (read_one(spec->sync_child_fd, &lookup_ready) != 0 || lookup_ready > 1U) {
        child_fail(spec, EPROTO);
    }
    const unsigned char *program = spec->base_program;
    size_t program_size = spec->base_program_size;
    if (lookup_ready) {
        program = spec->frozen_program;
        program_size = spec->frozen_program_size;
        if (spec->broker_transfer_fd < 0) {
            child_fail(spec, EBADF);
        }
    }

    int notify_fd = load_payload_filter(program, program_size,
                                        spec->want_wait_killable);
    if (notify_fd < 0 || probe_notify_fd(notify_fd) != 0) {
        child_fail(spec, errno);
    }
    if (send_payload_handoff(spec, notify_fd, lookup_ready) != 0) {
        child_fail(spec, errno);
    }
    unsigned char ack = 0;
    if (read_one(spec->control_fd, &ack) != 0 || ack != 0x01U) {
        child_fail(spec, EPROTO);
    }
    (void)syscall(SYS_close, notify_fd);
    if (spec->broker_transfer_fd >= 0) {
        (void)syscall(SYS_close, spec->broker_transfer_fd);
    }
    (void)syscall(SYS_close, spec->control_fd);

    report_status(spec->sync_child_fd, 0);
    unsigned char release = 0;
    if (read_one(spec->sync_child_fd, &release) != 0 || release != 'X') {
        _exit(127);
    }
    (void)syscall(SYS_close, spec->sync_child_fd);

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGURG);
    (void)sigprocmask(SIG_SETMASK, &blocked, NULL);
    execve(spec->exec_path, spec->argv, spec->envp);
    _exit(127);
}

pid_t agentsh_fork_payload(const struct agentsh_payload_spec *spec) {
    if (spec == NULL || spec->control_fd < 3 || spec->sync_parent_fd < 0 ||
        spec->sync_child_fd < 0 || spec->expected_parent_pid <= 0 ||
        spec->exec_path == NULL || spec->argv == NULL || spec->envp == NULL) {
        errno = EINVAL;
        return -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        payload_child(spec);
    }
    return pid;
}
