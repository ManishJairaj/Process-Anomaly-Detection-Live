#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>

#define PROCESS_NAME_LEN 64

typedef struct {
    uint64_t timestamp;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    int32_t syscall_id;
    char process_name[PROCESS_NAME_LEN];
} SyscallEvent;

void print_event(const SyscallEvent *event);
int create_test_event(SyscallEvent *event, int syscall_id);
#endif
