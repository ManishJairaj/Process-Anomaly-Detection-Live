#include <stdio.h>
#include "event.h"
#include <string.h>
#include <unistd.h>
#include <time.h>
void print_event(const SyscallEvent *event)
{
    printf("Timestamp    : %lu\n", event->timestamp);
    printf("PID          : %u\n", event->pid);
    printf("PPID         : %u\n", event->ppid);
    printf("UID          : %u\n", event->uid);
    printf("Syscall ID   : %d\n", event->syscall_id);
    printf("Process      : %s\n", event->process_name);
}

int create_test_event(SyscallEvent *event, int syscall_id)
{
    struct timespec ts;

    if (event == NULL)
        return -1;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    event->timestamp =
        (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    event->pid = getpid();
    event->ppid = getppid();
    event->uid = getuid();
    event->syscall_id = syscall_id;

    strncpy(event->process_name, "test_process",
            PROCESS_NAME_LEN - 1);

    event->process_name[PROCESS_NAME_LEN - 1] = '\0';

    return 0;
}
