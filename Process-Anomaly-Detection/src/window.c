#include "window.h"

void window_manager_init(WindowManager *manager)
{
    if (manager == NULL)
        return;

    manager->count = 0;

    for (size_t i = 0; i < MAX_TRACKED_PROCESSES; i++)
    {
        manager->windows[i].pid = 0;
        manager->windows[i].size = 0;
        manager->windows[i].active = 0;
    }
}

static PIDWindow *find_window(WindowManager *manager, uint32_t pid)
{
    for (size_t i = 0; i < manager->count; i++)
    {
        if (manager->windows[i].active &&
            manager->windows[i].pid == pid)
        {
            return &manager->windows[i];
        }
    }

    return NULL;
}

static PIDWindow *create_window(WindowManager *manager, uint32_t pid)
{
    if (manager->count >= MAX_TRACKED_PROCESSES)
        return NULL;

    PIDWindow *window = &manager->windows[manager->count];

    window->pid = pid;
    window->size = 0;
    window->active = 1;

    manager->count++;

    return window;
}

int window_add_event(WindowManager *manager,
                     const SyscallEvent *event,
                     NGram *ngram)
{
    PIDWindow *window;

    if (manager == NULL || event == NULL || ngram == NULL)
        return -1;

    window = find_window(manager, event->pid);

    if (window == NULL)
        window = create_window(manager, event->pid);

    if (window == NULL)
        return -1;

    if (window->size < NGRAM_SIZE)
    {
        window->values[window->size] = event->syscall_id;
        window->size++;
    }
    else
    {
        for (size_t i = 0; i < NGRAM_SIZE - 1; i++)
            window->values[i] = window->values[i + 1];

        window->values[NGRAM_SIZE - 1] = event->syscall_id;
    }

    if (window->size == NGRAM_SIZE)
    {
        for (size_t i = 0; i < NGRAM_SIZE; i++)
            ngram->values[i] = window->values[i];

        return 1;
    }

    return 0;
}
