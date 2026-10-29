#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

#include <bpf/libbpf.h>

#include "../include/event.h"
#include "../include/window.h"
#include "../include/model.h"
#include "syscall_collector.skel.h"

struct bpf_syscall_event
{
    unsigned long long timestamp;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    int syscall_id;
    char process_name[64];
};

struct trainer_state
{
    NormalModel model;
    WindowManager manager;
    pid_t own_pid;
    pid_t parent_pid;
    unsigned long events_seen;
    unsigned long ngrams_seen;
};

static volatile sig_atomic_t running = 1;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static int handle_event(void *context, void *data, size_t size)
{
    if (!running)
        return -1;

    struct trainer_state *state = context;
    const struct bpf_syscall_event *input = data;
    SyscallEvent event;
    NGram ngram;
    int result;

    if (size < sizeof(*input))
        return 0;

    if (input->pid == (unsigned int)state->own_pid ||
        (state->parent_pid > 1 && input->pid == (unsigned int)state->parent_pid))
    {
        return 0;
    }

    event.timestamp = input->timestamp;
    event.pid = input->pid;
    event.ppid = input->ppid;
    event.uid = input->uid;
    event.syscall_id = input->syscall_id;

    for (size_t i = 0; i < PROCESS_NAME_LEN; i++)
        event.process_name[i] = input->process_name[i];

    event.process_name[PROCESS_NAME_LEN - 1] = '\0';

    state->events_seen++;

    result = window_add_event(&state->manager, &event, &ngram);

    if (result == 1)
    {
        if (normal_model_add(&state->model, &ngram) == 0)
            state->ngrams_seen++;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct syscall_collector_bpf *skel = NULL;
    struct ring_buffer *ring_buffer = NULL;
    struct trainer_state state = {0};
    char *end = NULL;
    long duration = 60;
    time_t end_time;
    int err = 0;
    int exit_code = 1;

    if (argc > 2)
    {
        fprintf(stderr, "Usage: %s [duration_seconds]\n", argv[0]);
        return 1;
    }

    if (argc == 2)
    {
        errno = 0;
        duration = strtol(argv[1], &end, 10);

        if (errno != 0 || end == argv[1] || *end != '\0' ||
            duration < 1 || duration > 86400)
        {
            fprintf(stderr,
                    "Duration must be between 1 and 86400 seconds\n");
            return 1;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    state.own_pid = getpid();
    state.parent_pid = getppid();

    normal_model_init(&state.model);
    window_manager_init(&state.manager);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = syscall_collector_bpf__open_and_load();

    if (!skel)
    {
        fprintf(stderr, "Failed to load eBPF program\n");
        goto cleanup;
    }

    err = syscall_collector_bpf__attach(skel);

    if (err)
    {
        fprintf(stderr, "Failed to attach eBPF program: %d\n", err);
        goto cleanup;
    }

    ring_buffer = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        &state,
        NULL
    );

    if (!ring_buffer)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    end_time = time(NULL) + duration;

    printf("Benign Syscall Training Started\n");
    printf("===============================\n");
    printf("Duration: %ld seconds\n", duration);
    printf("Perform your usual benign activities in other terminals.\n");
    printf("Press Ctrl+C to finish training early.\n\n");
    fflush(stdout);

    while (running && time(NULL) < end_time)
    {
        err = ring_buffer__poll(ring_buffer, 100);

        if (err < 0)
        {
            if (err == -EINTR || !running)
                break;
            fprintf(stderr, "Ring buffer polling failed: %d\n", err);
            goto cleanup;
        }
    }

    if (state.ngrams_seen == 0)
    {
        fprintf(stderr,
                "No n-grams collected; the model was not saved.\n");
        goto cleanup;
    }

    normal_model_finalize(&state.model);

    if (normal_model_save(&state.model, "../normal_model.dat") != 0)
    {
        fprintf(stderr, "Failed to save normal_model.dat\n");
        goto cleanup;
    }

    printf("\nTraining Complete\n");
    printf("=================\n");
    printf("Syscall events collected : %lu\n", state.events_seen);
    printf("N-grams learned          : %lu\n", state.ngrams_seen);
    printf("Unique n-grams            : %zu\n", state.model.size);
    printf("Model saved to            : ../normal_model.dat\n");

    exit_code = 0;

cleanup:
    ring_buffer__free(ring_buffer);
    syscall_collector_bpf__destroy(skel);

    return exit_code;
}