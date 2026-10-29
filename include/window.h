#ifndef WINDOW_H
#define WINDOW_H

#include <stddef.h>
#include <stdint.h>
#include "event.h"
#include "ngram.h"

#define MAX_TRACKED_PROCESSES 1024

typedef struct {
    uint32_t pid;
    int values[NGRAM_SIZE];
    size_t size;
    int active;
} PIDWindow;

typedef struct {
    PIDWindow windows[MAX_TRACKED_PROCESSES];
    size_t count;
} WindowManager;

void window_manager_init(WindowManager *manager);

int window_add_event(WindowManager *manager,
                     const SyscallEvent *event,
                     NGram *ngram);

#endif
