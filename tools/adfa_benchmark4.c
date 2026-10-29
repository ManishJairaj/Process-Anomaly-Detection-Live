#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>

#define NGRAM4_SIZE 4
#define INITIAL_MODEL_CAPACITY 65536

static double anomaly_threshold = 0.05;

typedef struct {
    int values[NGRAM4_SIZE];
} NGram4;

typedef struct {
    NGram4 ngram;
    unsigned long count;
    double probability;
    int occupied;
} ModelEntry4;

typedef struct {
    ModelEntry4 *entries;
    size_t capacity;
    size_t size;
    unsigned long total_ngrams;
} NormalModel4;

typedef struct {
    unsigned long traces;
    unsigned long detected;
    unsigned long missed;
    unsigned long no_ngrams;
    unsigned long long total_ngrams;
    unsigned long long unseen_ngrams;
} EvaluationStats;

static inline int ngram4_equal(const NGram4 *a, const NGram4 *b)
{
    return (a->values[0] == b->values[0] &&
            a->values[1] == b->values[1] &&
            a->values[2] == b->values[2] &&
            a->values[3] == b->values[3]);
}

static inline uint32_t ngram4_hash(const NGram4 *ngram)
{
    uint32_t hash = 2166136261u;
    for (int i = 0; i < NGRAM4_SIZE; i++) {
        hash ^= (uint32_t)ngram->values[i];
        hash *= 16777619u;
    }
    return hash;
}

static void normal_model4_init(NormalModel4 *model, size_t initial_cap)
{
    model->capacity = initial_cap ? initial_cap : INITIAL_MODEL_CAPACITY;
    model->entries = calloc(model->capacity, sizeof(ModelEntry4));
    if (!model->entries) {
        fprintf(stderr, "Fatal: Out of memory for 4-gram model allocation.\n");
        exit(EXIT_FAILURE);
    }
    model->size = 0;
    model->total_ngrams = 0;
}

static void normal_model4_free(NormalModel4 *model)
{
    if (model && model->entries) {
        free(model->entries);
        model->entries = NULL;
    }
}

static int normal_model4_resize(NormalModel4 *model)
{
    size_t old_cap = model->capacity;
    ModelEntry4 *old_entries = model->entries;

    size_t new_cap = old_cap * 2;
    ModelEntry4 *new_entries = calloc(new_cap, sizeof(ModelEntry4));
    if (!new_entries) {
        fprintf(stderr, "Error: Unable to reallocate 4-gram model (cap %zu).\n", new_cap);
        return -1;
    }

    model->capacity = new_cap;
    model->entries = new_entries;

    for (size_t i = 0; i < old_cap; i++) {
        if (old_entries[i].occupied) {
            uint32_t idx = ngram4_hash(&old_entries[i].ngram) % new_cap;
            while (new_entries[idx].occupied) {
                idx = (idx + 1) % new_cap;
            }
            new_entries[idx] = old_entries[i];
        }
    }

    free(old_entries);
    return 0;
}

static int normal_model4_add(NormalModel4 *model, const NGram4 *ngram)
{
    if (!model || !ngram) return -1;

    if (model->size * 10 >= model->capacity * 7) {
        if (normal_model4_resize(model) != 0) {
            return -1;
        }
    }

    uint32_t idx = ngram4_hash(ngram) % model->capacity;
    while (model->entries[idx].occupied) {
        if (ngram4_equal(&model->entries[idx].ngram, ngram)) {
            model->entries[idx].count++;
            model->total_ngrams++;
            return 0;
        }
        idx = (idx + 1) % model->capacity;
    }

    model->entries[idx].ngram = *ngram;
    model->entries[idx].count = 1;
    model->entries[idx].probability = 0.0;
    model->entries[idx].occupied = 1;
    model->size++;
    model->total_ngrams++;

    return 0;
}

static int model4_contains(const NormalModel4 *model, const NGram4 *ngram)
{
    if (!model || !model->entries || model->capacity == 0) return 0;

    uint32_t idx = ngram4_hash(ngram) % model->capacity;
    while (model->entries[idx].occupied) {
        if (ngram4_equal(&model->entries[idx].ngram, ngram)) {
            return 1;
        }
        idx = (idx + 1) % model->capacity;
    }
    return 0;
}

static void normal_model4_finalize(NormalModel4 *model)
{
    if (!model || model->total_ngrams == 0) return;

    for (size_t i = 0; i < model->capacity; i++) {
        if (model->entries[i].occupied) {
            model->entries[i].probability =
                (double)model->entries[i].count / (double)model->total_ngrams;
        }
    }
}

static int process_trace(const char *path,
                         NormalModel4 *model,
                         int training,
                         EvaluationStats *stats,
                         int report_errors)
{
    FILE *file = fopen(path, "r");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    int window[NGRAM4_SIZE];
    size_t used = 0;
    int syscall_id;
    unsigned long long total = 0;
    unsigned long long unseen = 0;

    while (fscanf(file, "%d", &syscall_id) == 1) {
        if (used < NGRAM4_SIZE) {
            window[used++] = syscall_id;

            if (used < NGRAM4_SIZE)
                continue;
        } else {
            window[0] = window[1];
            window[1] = window[2];
            window[2] = window[3];
            window[3] = syscall_id;
        }

        NGram4 ngram;

        for (size_t i = 0; i < NGRAM4_SIZE; i++)
            ngram.values[i] = window[i];

        if (training) {
            if (normal_model4_add(model, &ngram) != 0) {
                fprintf(stderr,
                        "Model capacity exceeded while reading %s\n",
                        path);
                fclose(file);
                return -1;
            }
        } else {
            total++;

            if (!model4_contains(model, &ngram))
                unseen++;
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Error reading %s\n", path);
        fclose(file);
        return -1;
    }

    fclose(file);

    if (!training) {
        stats->traces++;
        stats->total_ngrams += total;
        stats->unseen_ngrams += unseen;

        if (total == 0) {
            stats->no_ngrams++;
        } else {
            double score = (double)unseen / (double)total;
            int detected = score >= anomaly_threshold;

            if (detected)
                stats->detected++;
            else
                stats->missed++;

            int is_validation =
                strstr(path, "Validation_Data_Master") != NULL;

            int is_attack =
                strstr(path, "Attack_Data_Master") != NULL;

            if (report_errors && is_validation && detected) {
                printf("FALSE POSITIVE | %s | Score: %.4f | Unseen: %llu/%llu\n",
                    path, score, unseen, total);
            } else if (report_errors && is_attack && !detected) {
                printf("FALSE NEGATIVE | %s | Score: %.4f | Unseen: %llu/%llu\n",
                    path, score, unseen, total);
            }
        }
    }

    return 0;
}

static int process_directory(const char *path,
                             NormalModel4 *model,
                             int training,
                             EvaluationStats *stats,
                             int report_errors)
{
    DIR *directory = opendir(path);

    if (directory == NULL) {
        perror(path);
        return -1;
    }

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char full_path[PATH_MAX];

        int length = snprintf(full_path, sizeof(full_path),
                              "%s/%s", path, entry->d_name);

        if (length < 0 || (size_t)length >= sizeof(full_path)) {
            fprintf(stderr, "Path too long: %s/%s\n",
                    path, entry->d_name);
            result = -1;
            break;
        }

        struct stat info;

        if (stat(full_path, &info) != 0) {
            perror(full_path);
            result = -1;
            break;
        }

        if (S_ISDIR(info.st_mode)) {
            if (process_directory(full_path, model,
                      training, stats, report_errors) != 0) {
                result = -1;
                break;
            }
        } else if (S_ISREG(info.st_mode)) {
            if (process_trace(full_path, model,
                  training, stats, report_errors) != 0) {
                result = -1;
                break;
            }
        }
    }

    closedir(directory);
    return result;
}

static void print_stats(const char *title,
                        const EvaluationStats *stats)
{
    printf("\n%s\n", title);
    printf("----------------------------------------\n");
    printf("Traces evaluated       : %lu\n", stats->traces);
    printf("Detected as anomalous  : %lu\n", stats->detected);
    printf("Not detected           : %lu\n", stats->missed);
    printf("Traces without 4-grams : %lu\n", stats->no_ngrams);
    printf("Total 4-grams           : %llu\n", stats->total_ngrams);
    printf("Unseen 4-grams          : %llu\n", stats->unseen_ngrams);

    if (stats->total_ngrams > 0) {
        double rate = 100.0 * (double)stats->unseen_ngrams /
                      (double)stats->total_ngrams;

        printf("Unseen 4-gram rate      : %.2f%%\n", rate);
    }
}

static void evaluate_attack_categories(
    const char *path,
    const NormalModel4 *model)
{
    DIR *directory = opendir(path);

    if (directory == NULL) {
        perror(path);
        return;
    }

    struct dirent *entry;

    printf("\nPER-ATTACK-FAMILY RESULTS (4-GRAM)\n");
    printf("----------------------------------------\n");

    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        char category_path[PATH_MAX];
        struct stat info;

        int length = snprintf(category_path,
                              sizeof(category_path),
                              "%s/%s", path, entry->d_name);

        if (length < 0 ||
            (size_t)length >= sizeof(category_path))
            continue;

        if (stat(category_path, &info) != 0 ||
            !S_ISDIR(info.st_mode))
            continue;

        EvaluationStats stats = {0};

        if (process_directory(category_path,
                      (NormalModel4 *)model,
                      0, &stats, 0) != 0) {
            fprintf(stderr, "Could not evaluate %s\n",
                    entry->d_name);
            continue;
        }

        double recall = stats.traces
            ? 100.0 * (double)stats.detected / stats.traces
            : 0.0;

        printf("%-25s %lu/%lu detected  Recall: %.2f%%\n",
               entry->d_name,
               stats.detected,
               stats.traces,
               recall);
    }

    closedir(directory);
}

int main(int argc, char *argv[])
{
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [threshold 0..1]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (argc == 2) {
        char *end;
        double value = strtod(argv[1], &end);

        if (end == argv[1] || *end != '\0' ||
            value < 0.0 || value > 1.0) {
            fprintf(stderr, "Threshold must be between 0 and 1.\n");
            return EXIT_FAILURE;
        }

        anomaly_threshold = value;
    }

    printf("Threshold used: %.2f (%.0f%%)\n",
           anomaly_threshold, anomaly_threshold * 100.0);
    const char *base = "datasets/ADFA-LD/ADFA-LD";

    char training_path[PATH_MAX];
    char validation_path[PATH_MAX];
    char attack_path[PATH_MAX];

    snprintf(training_path, sizeof(training_path),
             "%s/Training_Data_Master", base);
    snprintf(validation_path, sizeof(validation_path),
             "%s/Validation_Data_Master", base);
    snprintf(attack_path, sizeof(attack_path),
             "%s/Attack_Data_Master", base);

    NormalModel4 model;
    normal_model4_init(&model, INITIAL_MODEL_CAPACITY);

    EvaluationStats validation = {0};
    EvaluationStats attacks = {0};

    printf("ADFA-LD 4-Gram Offline Benchmark\n");
    printf("Training normal behavior...\n");

    if (process_directory(training_path, &model, 1, NULL, 0) != 0) {
        normal_model4_free(&model);
        return EXIT_FAILURE;
    }

    normal_model4_finalize(&model);

    printf("Training complete.\n");
    printf("Unique normal 4-grams : %zu\n", model.size);
    printf("Training 4-grams      : %lu\n", model.total_ngrams);
    printf("Model capacity        : %zu\n", model.capacity);
    printf("Model saved to disk   : No\n");

    printf("\nEvaluating validation traces...\n");

    if (process_directory(validation_path, &model, 0,
                       &validation, 1) != 0) {
        normal_model4_free(&model);
        return EXIT_FAILURE;
    }

    printf("Evaluating attack traces...\n");

    if (process_directory(attack_path, &model, 0,
                       &attacks, 1) != 0) {
        normal_model4_free(&model);
        return EXIT_FAILURE;
    }

    print_stats("NORMAL VALIDATION RESULTS (4-GRAM)", &validation);
    print_stats("ATTACK TRACE RESULTS (4-GRAM)", &attacks);

    unsigned long tp = attacks.detected;
    unsigned long fn = attacks.missed;
    unsigned long fp = validation.detected;
    unsigned long tn = validation.missed;

    printf("\nTRACE-LEVEL CLASSIFICATION METRICS (4-GRAM)\n");
    printf("----------------------------------------\n");
    printf("True positives  (attacks detected) : %lu\n", tp);
    printf("False negatives (attacks missed)   : %lu\n", fn);
    printf("False positives (normal flagged)   : %lu\n", fp);
    printf("True negatives  (normal accepted)   : %lu\n", tn);

    if (tp + fn > 0)
        printf("Attack recall    : %.2f%%\n",
               100.0 * (double)tp / (double)(tp + fn));

    if (tp + fp > 0)
        printf("Precision        : %.2f%%\n",
               100.0 * (double)tp / (double)(tp + fp));

    if (2 * tp + fp + fn > 0)
        printf("F1 score         : %.2f%%\n",
               100.0 * (double)(2 * tp) /
               (double)(2 * tp + fp + fn));

    if (fp + tn > 0)
        printf("False positive rate: %.2f%%\n",
               100.0 * (double)fp / (double)(fp + tn));

    evaluate_attack_categories(attack_path, &model);

    normal_model4_free(&model);
    return EXIT_SUCCESS;
}