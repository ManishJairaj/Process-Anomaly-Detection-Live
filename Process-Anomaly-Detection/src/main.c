#include <stdio.h>
#include <unistd.h>
#include "event.h"
#include "ngram.h"
#include "window.h"

int main(void)
{
    int syscalls[] = {
        2, 5,
        0, 6,
        0, 7,
        1, 8,
        3
    };

    uint32_t current_pid = (uint32_t)getpid();
    uint32_t second_pid = current_pid + 1;

    uint32_t pids[] = {
        current_pid, second_pid,
        current_pid, second_pid,
        current_pid, second_pid,
        current_pid, second_pid,
        current_pid
    };

    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);

    NGramTable table;
    WindowManager manager;

    ngram_table_init(&table);
    window_manager_init(&manager);

    for (size_t i = 0; i < count; i++)
    {
        SyscallEvent event;
        NGram ngram;

        if (create_test_event(&event, syscalls[i]) != 0)
        {
            fprintf(stderr, "Failed to create event\n");
            return 1;
        }

        event.pid = pids[i];

        int result = window_add_event(&manager, &event, &ngram);

        if (result == 1)
        {
            printf("PID %u: %d -> %d -> %d\n",
                   event.pid,
                   ngram.values[0],
                   ngram.values[1],
                   ngram.values[2]);

            ngram_table_add(&table, &ngram);
        }
    }

    printf("\nN-Gram Frequency Table\n");
    printf("----------------------\n");

    ngram_table_print(&table);

    return 0;
}
