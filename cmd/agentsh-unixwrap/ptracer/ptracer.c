/*
 * libagentsh-ptracer.so — LD_PRELOAD library for Yama ptrace_scope workaround.
 *
 * Under Yama ptrace_scope=1 (Ubuntu/Debian default), only ancestor processes
 * can use ProcessVMReadv on a target. In the agentsh wrap path, the server is
 * NOT an ancestor of child processes (PR_SET_PTRACER doesn't inherit across
 * fork). This library runs as an LD_PRELOAD constructor in every dynamically-
 * linked child process, calling prctl(PR_SET_PTRACER, server_pid) to authorize
 * the server to read the process's memory for seccomp path resolution.
 *
 * The server PID is read from AGENTSH_SERVER_PID. A command jailed in a
 * private PID namespace instead carries AGENTSH_PTRACER_ANY=1 because it cannot
 * name the trusted supervisor outside that namespace.
 *
 * Build: gcc -shared -fPIC -Os -o libagentsh-ptracer.so ptracer.c
 */

#include <sys/prctl.h>
#include <stdlib.h>

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif
#ifndef PR_SET_PTRACER_ANY
#define PR_SET_PTRACER_ANY ((unsigned long)-1)
#endif

__attribute__((constructor))
static void agentsh_set_ptracer(void) {
    const char *allow_any = getenv("AGENTSH_PTRACER_ANY");
    if (allow_any && allow_any[0] == '1' && allow_any[1] == '\0') {
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
        return;
    }

    const char *s = getenv("AGENTSH_SERVER_PID");
    if (s) {
        long pid = strtol(s, NULL, 10);
        if (pid > 0)
            prctl(PR_SET_PTRACER, (unsigned long)pid, 0, 0, 0);
    }
}
