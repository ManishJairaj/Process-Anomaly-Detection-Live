#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <bpf/libbpf.h>

#include "../include/event.h"
#include "../include/window.h"
#include "../include/model.h"
#include "../include/anomaly.h"
#include "../include/explanation.h"

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

static volatile sig_atomic_t running = 1;
static pid_t own_pid;
static pid_t parent_pid;
static int suspicious_only = 0;
static int quiet_mode = 0;

static FILE *dataset_file = NULL;
static uint64_t rows_written = 0;

static NormalModel model;
static WindowManager manager;

static int is_self_or_launcher_event(uint32_t event_pid)
{
    if (event_pid == (uint32_t)own_pid)
        return 1;

    if (parent_pid > 1 && event_pid == (uint32_t)parent_pid)
        return 1;

    return 0;
}

static void handle_signal(int signal)
{
    (void)signal;
    running = 0;
}

static int open_dataset_log(const char *path)
{
    dataset_file = fopen(path, "a+");

    if (dataset_file == NULL)
    {
        perror("Failed to open dataset CSV");
        return -1;
    }

    if (fseek(dataset_file, 0, SEEK_END) != 0)
    {
        perror("Failed to seek dataset CSV");
        fclose(dataset_file);
        dataset_file = NULL;
        return -1;
    }

    if (ftell(dataset_file) == 0)
    {
        fprintf(dataset_file,
                "monotonic_timestamp_ns,pid,process_name,"
                "syscall_1,syscall_2,syscall_3,"
                "anomaly_score,predicted_label\n");

        if (fflush(dataset_file) != 0)
        {
            perror("Failed to write dataset header");
            fclose(dataset_file);
            dataset_file = NULL;
            return -1;
        }
    }

    printf("Dataset logging enabled: %s\n", path);
    return 0;
}

static void log_dataset_row(const SyscallEvent *event,
                            const NGram *ngram,
                            double score,
                            int suspicious)
{
    if (dataset_file == NULL)
        return;

    int ret = fprintf(dataset_file,
                      "%" PRIu64 ",%u,\"%s\",%d,%d,%d,%.4f,%s\n",
                      (uint64_t)event->timestamp,
                      event->pid,
                      event->process_name,
                      ngram->values[0],
                      ngram->values[1],
                      ngram->values[2],
                      score,
                      suspicious ? "SUSPICIOUS" : "NORMAL");

    if (ret < 0)
    {
        fprintf(stderr, "Error: Failed to write dataset log row\n");
        return;
    }

    rows_written++;

    if (rows_written % 1000 == 0)
    {
        if (fflush(dataset_file) != 0)
        {
            perror("Error flushing dataset log CSV");
        }
    }
}

static void close_dataset_log(void)
{
    if (dataset_file != NULL)
    {
        if (fflush(dataset_file) != 0)
        {
            perror("Failed to flush dataset CSV on shutdown");
        }
        fclose(dataset_file);
        dataset_file = NULL;
    }
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -s, --suspicious-only  Print only suspicious events\n");
    printf("  -q, --quiet            Print detailed anomaly alerts only\n");
    printf("  -m, --model <path>     Path to trained model file\n");
    printf("  -o, --output <path>    Path to dataset CSV log file\n");
    printf("  -h, --help             Show this help message\n");
}

static void process_event(const struct bpf_syscall_event *input)
{
    SyscallEvent event;
    NGram ngram;

    event.timestamp = input->timestamp;
    event.pid = input->pid;
    event.ppid = input->ppid;
    event.uid = input->uid;
    event.syscall_id = input->syscall_id;

    for (size_t i = 0; i < PROCESS_NAME_LEN; i++)
        event.process_name[i] = input->process_name[i];

    event.process_name[PROCESS_NAME_LEN - 1] = '\0';

    int result = window_add_event(&manager, &event, &ngram);

    if (result != 1)
        return;

    double score = anomaly_score(&model, &ngram);
    int suspicious = anomaly_is_suspicious(score);

    log_dataset_row(&event, &ngram, score, suspicious);

    if (quiet_mode)
    {
        if (suspicious)
        {
            explain_anomaly(&event, &ngram, &model, score);
            fflush(stdout);
        }
        return;
    }

    if (suspicious_only)
    {
        if (suspicious)
        {
            printf("PID %u | Process %s | N-Gram: %d -> %d -> %d | Score: %.4f | SUSPICIOUS\n",
                   event.pid,
                   event.process_name,
                   ngram.values[0],
                   ngram.values[1],
                   ngram.values[2],
                   score);

            explain_anomaly(&event, &ngram, &model, score);
            fflush(stdout);
        }
        return;
    }

    printf("PID %u | Process %s | N-Gram: %d -> %d -> %d | Score: %.4f",
           event.pid,
           event.process_name,
           ngram.values[0],
           ngram.values[1],
           ngram.values[2],
           score);

    if (suspicious)
    {
        printf(" | SUSPICIOUS\n");
        explain_anomaly(&event, &ngram, &model, score);
    }
    else
    {
        printf(" | NORMAL\n");
    }

    fflush(stdout);
}

static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;

    if (!running)
        return -1;

    if (data == NULL || size < sizeof(struct bpf_syscall_event))
        return 0;

    const struct bpf_syscall_event *event = data;

    if (is_self_or_launcher_event(event->pid))
        return 0;

    process_event(event);

    return 0;
}

int main(int argc, char **argv)
{
    struct syscall_collector_bpf *skel = NULL;
    struct ring_buffer *ring_buffer = NULL;

    const char *model_path = NULL;
    const char *dataset_path = NULL;
    const char *custom_output_path = NULL;

    int err;
    int exit_status = 1;

    own_pid = getpid();
    parent_pid = getppid();

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-s") == 0 ||
            strcmp(argv[i], "--suspicious-only") == 0)
        {
            suspicious_only = 1;
        }
        else if (strcmp(argv[i], "-q") == 0 ||
                 strcmp(argv[i], "--quiet") == 0)
        {
            quiet_mode = 1;
        }
        else if (strcmp(argv[i], "-m") == 0 ||
                 strcmp(argv[i], "--model") == 0)
        {
            if (i + 1 < argc)
                model_path = argv[++i];
            else
            {
                fprintf(stderr, "Error: --model requires a file path\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-o") == 0 ||
                 strcmp(argv[i], "--output") == 0)
        {
            if (i + 1 < argc)
                custom_output_path = argv[++i];
            else
            {
                fprintf(stderr, "Error: --output requires a file path\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-h") == 0 ||
                 strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else
        {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1 ||
        sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction");
        return 1;
    }

    normal_model_init(&model);
    window_manager_init(&manager);

    if (model_path != NULL)
    {
        if (normal_model_load(&model, model_path) != 0)
        {
            fprintf(stderr, "Failed to load model: %s\n", model_path);
            goto cleanup;
        }

        dataset_path = "syscall_dataset.csv";
    }
    else
    {
        if (normal_model_load(&model, "normal_model.dat") == 0)
        {
            dataset_path = "syscall_dataset.csv";
        }
        else if (normal_model_load(&model, "../normal_model.dat") == 0)
        {
            dataset_path = "../syscall_dataset.csv";
        }
        else
        {
            fprintf(stderr,
                    "Failed to load model from normal_model.dat "
                    "or ../normal_model.dat\n");
            goto cleanup;
        }
    }

    if (custom_output_path != NULL)
    {
        dataset_path = custom_output_path;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = syscall_collector_bpf__open_and_load();

    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF program\n");
        goto cleanup;
    }

    err = syscall_collector_bpf__attach(skel);

    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    ring_buffer = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!ring_buffer)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if (open_dataset_log(dataset_path) != 0)
        goto cleanup;

    printf("\nReal-Time Process Anomaly Detection Started\n");
    printf("===========================================\n");
    printf("Detector PID: %d | Launcher PID: %d\n", own_pid, parent_pid);
    printf("Normal model loaded successfully\n");

    if (suspicious_only)
        printf("Mode: Showing SUSPICIOUS events only\n");
    else if (quiet_mode)
        printf("Mode: Quiet (Detailed anomaly alerts only)\n");
    else
        printf("Mode: Verbose (All syscall events)\n");

    printf("Monitoring real Linux syscalls... (Press Ctrl+C to stop)\n\n");
    fflush(stdout);

    exit_status = 0;

    while (running)
    {
        err = ring_buffer__poll(ring_buffer, 100);

        if (err < 0)
        {
            if (err == -EINTR || !running)
                break;

            fprintf(stderr, "Ring buffer polling failed: %d\n", err);
            exit_status = 1;
            break;
        }
    }

    printf("\nShutting down eBPF detector cleanly...\n");

cleanup:
    close_dataset_log();

    if (ring_buffer != NULL)
        ring_buffer__free(ring_buffer);

    if (skel != NULL)
        syscall_collector_bpf__destroy(skel);

    if (rows_written > 0)
        printf("Dataset rows written this run: %" PRIu64 "\n", rows_written);

    if (exit_status == 0)
        printf("Detector stopped cleanly.\n");

    return exit_status;
}