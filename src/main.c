#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "event.h"
#include "window.h"
#include "model.h"
#include "anomaly.h"
#include "explanation.h"

static FILE *dataset_file = NULL;
static uint64_t rows_written = 0;

static int open_dataset_log(const char *path)
{
    dataset_file = fopen(path, "a");

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
        fflush(dataset_file);
    }

    return 0;
}

static void log_dataset_row(const SyscallEvent *event,
                            const NGram *ngram,
                            double score,
                            int suspicious)
{
    if (dataset_file == NULL)
        return;

    fprintf(dataset_file,
            "%" PRIu64 ",%u,\"%s\",%d,%d,%d,%.4f,%s\n",
            (uint64_t)event->timestamp,
            event->pid,
            event->process_name,
            ngram->values[0],
            ngram->values[1],
            ngram->values[2],
            score,
            suspicious ? "SUSPICIOUS" : "NORMAL");

    rows_written++;

    if (rows_written % 1000 == 0)
        fflush(dataset_file);
}

int main(void)
{
    int syscalls[] = {
        2, 0, 0, 1, 3,
        2, 0, 0, 1, 3,
        9, 8, 7, 6
    };

    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);
    uint32_t pid = (uint32_t)getpid();

    NormalModel model;
    WindowManager manager;

    normal_model_init(&model);
    window_manager_init(&manager);

    if (normal_model_load(&model, "normal_model.dat") != 0)
    {
        fprintf(stderr, "Failed to load normal model\n");
        return 1;
    }

    if (open_dataset_log("syscall_dataset.csv") != 0)
        return 1;

    printf("Real-Time Anomaly Detection Test\n");
    printf("=================================\n\n");

    for (size_t i = 0; i < count; i++)
    {
        SyscallEvent event;
        NGram ngram;

        if (create_test_event(&event, syscalls[i]) != 0)
        {
            fprintf(stderr, "Failed to create event\n");
            fclose(dataset_file);
            return 1;
        }

        event.pid = pid;

        int result = window_add_event(&manager, &event, &ngram);

        if (result < 0)
        {
            fprintf(stderr, "Failed to update syscall window\n");
            fclose(dataset_file);
            return 1;
        }

        if (result != 1)
            continue;

        double score = anomaly_score(&model, &ngram);
        int suspicious = anomaly_is_suspicious(score);

        log_dataset_row(&event, &ngram, score, suspicious);

        printf("PID %u | N-Gram: %d -> %d -> %d | Score: %.4f",
               event.pid,
               ngram.values[0],
               ngram.values[1],
               ngram.values[2],
               score);

        if (suspicious)
        {
            printf(" | SUSPICIOUS\n");

            explain_anomaly(&event,
                            &ngram,
                            &model,
                            score);
        }
        else
        {
            printf(" | NORMAL\n");
        }
    }

    fflush(dataset_file);
    fclose(dataset_file);
    dataset_file = NULL;

    printf("\nDataset saved to syscall_dataset.csv\n");
    printf("Rows logged: %" PRIu64 "\n", rows_written);

    return 0;
}

