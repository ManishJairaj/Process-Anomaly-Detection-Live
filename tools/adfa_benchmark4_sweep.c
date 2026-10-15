#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>

#define N 4
#define INITIAL_CAPACITY 65536
#define MAX_THRESHOLD 0.30
#define TARGET_FPR 0.05

typedef struct {
    int v[N];
} NGram;

typedef struct {
    NGram gram;
    unsigned char used;
} Entry;

typedef struct {
    Entry *entries;
    size_t capacity;
    size_t size;
} Model;

typedef struct {
    char path[PATH_MAX];
    double score;
    unsigned long long total;
    unsigned long long unseen;
    int has_grams;
} Trace;

typedef struct {
    Trace *items;
    size_t count;
    size_t capacity;
} TraceList;

typedef struct {
    unsigned long tp, fn, fp, tn;
    unsigned long no_grams;
} Metrics;

static int equal_gram(const NGram *a, const NGram *b)
{
    for (int i = 0; i < N; i++)
        if (a->v[i] != b->v[i])
            return 0;
    return 1;
}

static uint32_t hash_gram(const NGram *g)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < N; i++) {
        h ^= (uint32_t)g->v[i];
        h *= 16777619u;
    }
    return h;
}

static int model_init(Model *m)
{
    m->capacity = INITIAL_CAPACITY;
    m->size = 0;
    m->entries = calloc(m->capacity, sizeof(*m->entries));
    return m->entries != NULL ? 0 : -1;
}

static int model_resize(Model *m)
{
    size_t old_capacity = m->capacity;
    Entry *old_entries = m->entries;
    size_t new_capacity = old_capacity * 2;
    Entry *new_entries = calloc(new_capacity, sizeof(*new_entries));

    if (!new_entries)
        return -1;

    m->entries = new_entries;
    m->capacity = new_capacity;
    m->size = 0;

    for (size_t i = 0; i < old_capacity; i++) {
        if (!old_entries[i].used)
            continue;

        size_t pos = hash_gram(&old_entries[i].gram) % m->capacity;
        while (m->entries[pos].used)
            pos = (pos + 1) % m->capacity;

        m->entries[pos] = old_entries[i];
        m->size++;
    }

    free(old_entries);
    return 0;
}

static int model_add(Model *m, const NGram *g)
{
    if (m->size * 10 >= m->capacity * 7) {
        if (model_resize(m) != 0)
            return -1;
    }

    size_t pos = hash_gram(g) % m->capacity;
    while (m->entries[pos].used) {
        if (equal_gram(&m->entries[pos].gram, g))
            return 0;
        pos = (pos + 1) % m->capacity;
    }

    m->entries[pos].gram = *g;
    m->entries[pos].used = 1;
    m->size++;
    return 0;
}

static int model_contains(const Model *m, const NGram *g)
{
    size_t pos = hash_gram(g) % m->capacity;
    size_t start = pos;

    while (m->entries[pos].used) {
        if (equal_gram(&m->entries[pos].gram, g))
            return 1;
        pos = (pos + 1) % m->capacity;
        if (pos == start)
            break;
    }
    return 0;
}

static int list_add(TraceList *list, const Trace *t)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 1024;
        Trace *new_items = realloc(list->items,
                                   new_capacity * sizeof(*new_items));
        if (!new_items)
            return -1;
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = *t;
    return 0;
}

static int train_trace(const char *path, Model *model)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }

    int window[N];
    size_t used = 0;
    int id, result = 0;

    while (fscanf(f, "%d", &id) == 1) {
        if (used < N) {
            window[used++] = id;
            if (used < N)
                continue;
        } else {
            memmove(window, window + 1, (N - 1) * sizeof(window[0]));
            window[N - 1] = id;
        }

        NGram g;
        memcpy(g.v, window, sizeof(window));

        if (model_add(model, &g) != 0) {
            fprintf(stderr, "Could not grow model while reading %s\n", path);
            result = -1;
            break;
        }
    }

    if (ferror(f)) {
        fprintf(stderr, "Read error: %s\n", path);
        result = -1;
    }

    fclose(f);
    return result;
}

static int score_trace(const char *path, const Model *model, TraceList *list)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return -1;
    }

    Trace t = {0};
    if (snprintf(t.path, sizeof(t.path), "%s", path) >=
        (int)sizeof(t.path)) {
        fprintf(stderr, "Trace path too long: %s\n", path);
        fclose(f);
        return -1;
    }

    int window[N];
    size_t used = 0;
    int id;

    while (fscanf(f, "%d", &id) == 1) {
        if (used < N) {
            window[used++] = id;
            if (used < N)
                continue;
        } else {
            memmove(window, window + 1, (N - 1) * sizeof(window[0]));
            window[N - 1] = id;
        }

        NGram g;
        memcpy(g.v, window, sizeof(window));
        t.total++;

        if (!model_contains(model, &g))
            t.unseen++;
    }

    if (ferror(f)) {
        fprintf(stderr, "Read error: %s\n", path);
        fclose(f);
        return -1;
    }

    fclose(f);
    t.has_grams = t.total > 0;
    t.score = t.has_grams ? (double)t.unseen / (double)t.total : 0.0;

    if (list_add(list, &t) != 0) {
        fprintf(stderr, "Out of memory storing trace results\n");
        return -1;
    }

    return 0;
}

static int walk_directory(const char *path, Model *model,
                          TraceList *list, int training)
{
    DIR *dir = opendir(path);
    if (!dir) {
        perror(path);
        return -1;
    }

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;

        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full)) {
            fprintf(stderr, "Path too long under %s\n", path);
            result = -1;
            break;
        }

        struct stat st;
        if (stat(full, &st) != 0) {
            perror(full);
            result = -1;
            break;
        }

        if (S_ISDIR(st.st_mode)) {
            if (walk_directory(full, model, list, training) != 0) {
                result = -1;
                break;
            }
        } else if (S_ISREG(st.st_mode)) {
            int rc = training ? train_trace(full, model)
                              : score_trace(full, model, list);
            if (rc != 0) {
                result = -1;
                break;
            }
        }
    }

    closedir(dir);
    return result;
}

static Metrics evaluate(const TraceList *traces, double threshold,
                        int is_attack)
{
    Metrics m = {0};

    for (size_t i = 0; i < traces->count; i++) {
        const Trace *t = &traces->items[i];

        if (!t->has_grams) {
            m.no_grams++;
            if (is_attack)
                m.fn++;
            else
                m.tn++;
            continue;
        }

        int detected = t->score >= threshold;

        if (is_attack) {
            if (detected) m.tp++;
            else m.fn++;
        } else {
            if (detected) m.fp++;
            else m.tn++;
        }
    }

    return m;
}

static double fpr_of(Metrics m)
{
    unsigned long total = m.fp + m.tn;
    return total ? (double)m.fp / total : 0.0;
}

static double tnr_of(Metrics m)
{
    unsigned long total = m.fp + m.tn;
    return total ? (double)m.tn / total : 0.0;
}

static int collect_thresholds(const TraceList *validation,
                              double *selected, Metrics *selected_metrics)
{
    int found = 0;
    double best_tnr = -1.0;
    double best_threshold = 0.0;

    printf("\nVALIDATION THRESHOLD SWEEP (0.01 TO 0.30)\n");
    printf("Threshold  Flagged  Accepted  FPR(%%)  TNR(%%)  Meets target\n");

    for (int step = 1; step <= 30; step++) {
        double threshold = step / 100.0;
        Metrics m = evaluate(validation, threshold, 0);
        double fpr = fpr_of(m);
        double tnr = tnr_of(m);

        printf("%.2f       %-8lu %-9lu %-7.2f %-7.2f %s\n",
               threshold, m.fp, m.tn, fpr * 100.0, tnr * 100.0,
               fpr <= TARGET_FPR ? "YES" : "NO");

        if (fpr <= TARGET_FPR &&
            (!found || tnr > best_tnr ||
             (tnr == best_tnr && threshold < best_threshold))) {
            found = 1;
            best_tnr = tnr;
            best_threshold = threshold;
            *selected_metrics = m;
        }
    }

    if (found)
        *selected = best_threshold;

    return found;
}

static void print_final(const TraceList *validation,
                        const TraceList *attacks, double threshold)
{
    Metrics val = evaluate(validation, threshold, 0);
    Metrics atk = evaluate(attacks, threshold, 1);

    double recall = atk.tp + atk.fn
        ? (double)atk.tp / (atk.tp + atk.fn) : 0.0;
    double precision = atk.tp + val.fp
        ? (double)atk.tp / (atk.tp + val.fp) : 0.0;
    double f1 = 2 * atk.tp + val.fp + atk.fn
        ? (double)(2 * atk.tp) / (2 * atk.tp + val.fp + atk.fn) : 0.0;

    printf("\nFINAL EVALUATION AT THRESHOLD %.2f\n", threshold);
    printf("Validation traces: %zu (zero 4-grams: %lu)\n",
           validation->count, val.no_grams);
    printf("Attack traces    : %zu (zero 4-grams: %lu)\n",
           attacks->count, atk.no_grams);
    printf("TP: %lu\nFN: %lu\nFP: %lu\nTN: %lu\n",
           atk.tp, atk.fn, val.fp, val.tn);
    printf("Attack Recall   : %.2f%%\n", recall * 100.0);
    printf("Precision       : %.2f%%\n", precision * 100.0);
    printf("F1 Score        : %.2f%%\n", f1 * 100.0);
    printf("Validation FPR  : %.2f%%\n", fpr_of(val) * 100.0);
    printf("Validation TNR  : %.2f%%\n", tnr_of(val) * 100.0);
}

int main(void)
{
    const char *base = "datasets/ADFA-LD/ADFA-LD";
    char train_path[PATH_MAX], val_path[PATH_MAX], attack_path[PATH_MAX];

    snprintf(train_path, sizeof(train_path), "%s/Training_Data_Master", base);
    snprintf(val_path, sizeof(val_path), "%s/Validation_Data_Master", base);
    snprintf(attack_path, sizeof(attack_path), "%s/Attack_Data_Master", base);

    Model model = {0};
    TraceList validation = {0}, attacks = {0};

    if (model_init(&model) != 0) {
        fprintf(stderr, "Could not allocate model\n");
        return EXIT_FAILURE;
    }

    printf("ADFA-LD 4-Gram Stage 9.9 Threshold Sweep\n");
    printf("Training normal behavior model...\n");

    if (walk_directory(train_path, &model, NULL, 1) != 0)
        goto fail;

    printf("Unique normal 4-grams: %zu\n", model.size);
    printf("Scoring validation traces...\n");

    if (walk_directory(val_path, &model, &validation, 0) != 0)
        goto fail;

    printf("Scoring attack traces...\n");

    if (walk_directory(attack_path, &model, &attacks, 0) != 0)
        goto fail;

    printf("Validation traces: %zu\n", validation.count);
    printf("Attack traces: %zu\n", attacks.count);

    double selected = 0.0;
    Metrics selected_metrics = {0};

    if (!collect_thresholds(&validation, &selected, &selected_metrics)) {
        printf("\nNO QUALIFYING THRESHOLD FOUND.\n");
        printf("No threshold from 0.01 through 0.30 achieves validation FPR <= 5%%.\n");
        printf("No attack-selected threshold will be substituted.\n");
        goto cleanup;
    }

    printf("\nSELECTED THRESHOLD: %.2f\n", selected);
    printf("Validation FPR: %.2f%%\n", fpr_of(selected_metrics) * 100.0);
    printf("Validation TNR: %.2f%%\n", tnr_of(selected_metrics));
    print_final(&validation, &attacks, selected);

cleanup:
    free(model.entries);
    free(validation.items);
    free(attacks.items);
    return EXIT_SUCCESS;

fail:
    free(model.entries);
    free(validation.items);
    free(attacks.items);
    return EXIT_FAILURE;
}
