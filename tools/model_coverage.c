#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model.h"
#include "ngram.h"

#define LINE_SIZE 512

static int model_contains(const NormalModel *model, const NGram *target)
{
    for (size_t i = 0; i < model->size; i++)
    {
        if (ngram_equal(&model->entries[i].ngram, target))
            return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    const char *model_path = argc > 1 ? argv[1] : "normal_model.dat";
    const char *csv_path = argc > 2 ? argv[2] : "syscall_dataset.csv";

    NormalModel model;
    normal_model_init(&model);

    if (normal_model_load(&model, model_path) != 0)
    {
        fprintf(stderr, "Cannot load model: %s\n", model_path);
        return 1;
    }

    FILE *file = fopen(csv_path, "r");
    if (file == NULL)
    {
        perror(csv_path);
        return 1;
    }

    char line[LINE_SIZE];
    unsigned long total = 0, seen = 0, unseen = 0;
    unsigned long normal_seen = 0, normal_unseen = 0;
    unsigned long suspicious_seen = 0, suspicious_unseen = 0;

    if (fgets(line, sizeof(line), file) == NULL)
    {
        fclose(file);
        fprintf(stderr, "CSV is empty.\n");
        return 1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *saveptr = NULL;
        char *fields[8];

        fields[0] = strtok_r(line, ",", &saveptr);
        int valid = fields[0] != NULL;

        for (int i = 1; i < 8 && valid; i++)
        {
            fields[i] = strtok_r(NULL, ",", &saveptr);
            if (fields[i] == NULL)
                valid = 0;
        }

        if (!valid)
            continue;

        NGram ngram = {0};
        ngram.values[0] = atoi(fields[3]);
        ngram.values[1] = atoi(fields[4]);
        ngram.values[2] = atoi(fields[5]);

        int is_seen = model_contains(&model, &ngram);
        int is_suspicious = strstr(fields[7], "SUSPICIOUS") != NULL;

        total++;

        if (is_seen)
            seen++;
        else
            unseen++;

        if (is_suspicious && is_seen)
            suspicious_seen++;
        else if (is_suspicious)
            suspicious_unseen++;
        else if (is_seen)
            normal_seen++;
        else
            normal_unseen++;
    }

    fclose(file);

    printf("Model Coverage Report\n");
    printf("=====================\n");
    printf("Dataset rows: %lu\n", total);
    printf("Model-seen rows: %lu (%.2f%%)\n",
           seen, total ? 100.0 * seen / total : 0.0);
    printf("Model-unseen rows: %lu (%.2f%%)\n",
           unseen, total ? 100.0 * unseen / total : 0.0);
    printf("\nExisting labels compared with model:\n");
    printf("NORMAL and seen: %lu\n", normal_seen);
    printf("NORMAL but unseen: %lu\n", normal_unseen);
    printf("SUSPICIOUS and seen: %lu\n", suspicious_seen);
    printf("SUSPICIOUS and unseen: %lu\n", suspicious_unseen);

    return 0;
}