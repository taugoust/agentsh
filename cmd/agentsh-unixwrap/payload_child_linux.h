#ifndef AGENTSH_PAYLOAD_CHILD_LINUX_H
#define AGENTSH_PAYLOAD_CHILD_LINUX_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct agentsh_payload_spec {
    int control_fd;
    int sync_parent_fd;
    int sync_child_fd;
    int broker_parent_fd;
    int broker_transfer_fd;
    int expected_parent_pid;
    int command_jail;
    int want_wait_killable;
    const unsigned char *base_program;
    size_t base_program_size;
    const unsigned char *frozen_program;
    size_t frozen_program_size;
    const char *exec_path;
    char *const *argv;
    char *const *envp;
};

pid_t agentsh_fork_payload(const struct agentsh_payload_spec *spec);

#endif
