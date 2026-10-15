/*
 * adfa_model_eval.c — Unified ADFA-LD model evaluation
 *
 * Compares 3-gram and 4-gram models with an extended threshold sweep.
 * All scoring uses the unseen-n-gram ratio: score = unseen / total.
 * Threshold is selected from validation-only data (no attack peeking).
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -Iinclude -o tools/adfa_model_eval \
 *       tools/adfa_model_eval.c src/ngram.c src/event.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <math.h>

/* ------------------------------------------------------------------ */
/* Hash-set model for arbitrary n-gram sizes                          */
/* ------------------------------------------------------------------ */
#define INITIAL_CAPACITY 65536
#define MAX_N 8

typedef struct {
    int v[MAX_N];
} NGram;

typedef struct {
    NGram gram;
    unsigned char used;
} Entry;

typedef struct {
    Entry *entries;
    size_t capacity;
    size_t size;
    int n;                   /* n-gram size */
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

/* ------------------------------------------------------------------ */
/* Hash-set operations                                                */
/* ------------------------------------------------------------------ */
static uint32_t hash_gram(const NGram *g, int n)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) {
        h ^= (uint32_t)g->v[i];
        h *= 16777619u;
    }
    return h;
}

static int equal_gram(const NGram *a, const NGram *b, int n)
{
    for (int i = 0; i < n; i++)
        if (a->v[i] != b->v[i])
            return 0;
    return 1;
}

static int model_init(Model *m, int n)
{
    m->capacity = INITIAL_CAPACITY;
    m->size = 0;
    m->n = n;
    m->entries = calloc(m->capacity, sizeof(*m->entries));
    return m->entries != NULL ? 0 : -1;
}

static void model_free(Model *m)
{
    free(m->entries);
    m->entries = NULL;
    m->size = 0;
}

static int model_resize(Model *m)
{
    size_t old_cap = m->capacity;
    Entry *old = m->entries;
    size_t new_cap = old_cap * 2;
    Entry *new_ent = calloc(new_cap, sizeof(*new_ent));
    if (!new_ent) return -1;

    m->entries = new_ent;
    m->capacity = new_cap;
    m->size = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (!old[i].used) continue;
        size_t pos = hash_gram(&old[i].gram, m->n) % new_cap;
        while (new_ent[pos].used)
            pos = (pos + 1) % new_cap;
        new_ent[pos] = old[i];
        m->size++;
    }
    free(old);
    return 0;
}

static int model_add(Model *m, const NGram *g)
{
    if (m->size * 10 >= m->capacity * 7) {
        if (model_resize(m) != 0) return -1;
    }
    size_t pos = hash_gram(g, m->n) % m->capacity;
    while (m->entries[pos].used) {
        if (equal_gram(&m->entries[pos].gram, g, m->n))
            return 0;   /* already present */
        pos = (pos + 1) % m->capacity;
    }
    m->entries[pos].gram = *g;
    m->entries[pos].used = 1;
    m->size++;
    return 0;
}

static int model_contains(const Model *m, const NGram *g)
{
    size_t pos = hash_gram(g, m->n) % m->capacity;
    size_t start = pos;
    while (m->entries[pos].used) {
        if (equal_gram(&m->entries[pos].gram, g, m->n))
            return 1;
        pos = (pos + 1) % m->capacity;
        if (pos == start) break;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Trace list operations                                              */
/* ------------------------------------------------------------------ */
static int list_add(TraceList *list, const Trace *t)
{
    if (list->count == list->capacity) {
        size_t new_cap = list->capacity ? list->capacity * 2 : 1024;
        Trace *tmp = realloc(list->items, new_cap * sizeof(*tmp));
        if (!tmp) return -1;
        list->items = tmp;
        list->capacity = new_cap;
    }
    list->items[list->count++] = *t;
    return 0;
}

static void list_free(TraceList *list)
{
    free(list->items);
    list->items = NULL;
    list->count = list->capacity = 0;
}

/* ------------------------------------------------------------------ */
/* File I/O                                                           */
/* ------------------------------------------------------------------ */
static int train_trace(const char *path, Model *model)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    int window[MAX_N];
    size_t used = 0;
    int id, n = model->n;

    while (fscanf(f, "%d", &id) == 1) {
        if (used < (size_t)n) {
            window[used++] = id;
            if (used < (size_t)n) continue;
        } else {
            memmove(window, window + 1, (n - 1) * sizeof(int));
            window[n - 1] = id;
        }
        NGram g = {{0}};
        memcpy(g.v, window, n * sizeof(int));
        if (model_add(model, &g) != 0) {
            fprintf(stderr, "Model allocation failed on %s\n", path);
            fclose(f);
            return -1;
        }
    }

    if (ferror(f)) {
        fprintf(stderr, "Read error: %s\n", path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int score_trace(const char *path, const Model *model, TraceList *list)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    Trace t = {0};
    snprintf(t.path, sizeof(t.path), "%s", path);

    int window[MAX_N];
    size_t used = 0;
    int id, n = model->n;

    while (fscanf(f, "%d", &id) == 1) {
        if (used < (size_t)n) {
            window[used++] = id;
            if (used < (size_t)n) continue;
        } else {
            memmove(window, window + 1, (n - 1) * sizeof(int));
            window[n - 1] = id;
        }
        NGram g = {{0}};
        memcpy(g.v, window, n * sizeof(int));
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
    return list_add(list, &t);
}

static int walk_directory(const char *path, Model *model,
                          TraceList *list, int training)
{
    DIR *dir = opendir(path);
    if (!dir) { perror(path); return -1; }

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char full[PATH_MAX];
        int len = snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(full)) {
            fprintf(stderr, "Path too long under %s\n", path);
            result = -1; break;
        }
        struct stat st;
        if (stat(full, &st) != 0) { perror(full); result = -1; break; }
        if (S_ISDIR(st.st_mode)) {
            if (walk_directory(full, model, list, training) != 0) {
                result = -1; break;
            }
        } else if (S_ISREG(st.st_mode)) {
            int rc = training ? train_trace(full, model)
                              : score_trace(full, model, list);
            if (rc != 0) { result = -1; break; }
        }
    }
    closedir(dir);
    return result;
}

/* ------------------------------------------------------------------ */
/* Evaluation helpers                                                 */
/* ------------------------------------------------------------------ */
static Metrics evaluate(const TraceList *traces, double threshold, int is_attack)
{
    Metrics m = {0};
    for (size_t i = 0; i < traces->count; i++) {
        const Trace *t = &traces->items[i];
        if (!t->has_grams) {
            m.no_grams++;
            /* Traces with no n-grams are treated as NOT detected (conservative). */
            if (is_attack) m.fn++; else m.tn++;
            continue;
        }
        int detected = t->score >= threshold;
        if (is_attack) {
            if (detected) m.tp++; else m.fn++;
        } else {
            if (detected) m.fp++; else m.tn++;
        }
    }
    return m;
}

static double safe_div(double num, double den)
{
    return den > 0.0 ? num / den : 0.0;
}

/* ------------------------------------------------------------------ */
/* Threshold sweep — extended range with finer granularity            */
/* ------------------------------------------------------------------ */
typedef struct {
    double threshold;
    double fpr;
    double recall;
    double precision;
    double f1;
    Metrics val;
    Metrics atk;
} SweepPoint;

static void run_sweep(const TraceList *validation, const TraceList *attacks,
                      double start, double end, double step,
                      SweepPoint *best_5pct,   /* best at ≤5% FPR */
                      SweepPoint *best_10pct,  /* best at ≤10% FPR */
                      SweepPoint *best_any)     /* lowest FPR overall */
{
    printf("\n%-10s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %s\n",
           "Threshold", "FP", "TN", "FPR%", "TP", "FN", "Recall%", "F1%", "Target");

    best_5pct->fpr = 2.0;
    best_10pct->fpr = 2.0;
    best_any->fpr = 2.0;

    for (double th = start; th <= end + 1e-9; th += step) {
        Metrics val = evaluate(validation, th, 0);
        Metrics atk = evaluate(attacks, th, 1);

        double fpr = safe_div((double)val.fp, (double)(val.fp + val.tn));
        double recall = safe_div((double)atk.tp, (double)(atk.tp + atk.fn));
        double precision = safe_div((double)atk.tp, (double)(atk.tp + val.fp));
        double f1 = safe_div(2.0 * atk.tp, 2.0 * atk.tp + val.fp + atk.fn);

        const char *tag = fpr <= 0.05 ? "<=5%" :
                          fpr <= 0.10 ? "<=10%" : "";

        printf("%-10.4f %-8lu %-8lu %-8.2f %-8lu %-8lu %-8.2f %-8.2f %s\n",
               th, val.fp, val.tn, fpr * 100, atk.tp, atk.fn,
               recall * 100, f1 * 100, tag);

        SweepPoint sp = {th, fpr, recall, precision, f1, val, atk};

        /* Track best at ≤5% FPR (lowest threshold = most sensitive) */
        if (fpr <= 0.05) {
            if (best_5pct->fpr > 1.0 || th < best_5pct->threshold) {
                *best_5pct = sp;
            }
        }
        /* Track best at ≤10% FPR */
        if (fpr <= 0.10) {
            if (best_10pct->fpr > 1.0 || th < best_10pct->threshold) {
                *best_10pct = sp;
            }
        }
        /* Track lowest FPR achievable */
        if (fpr < best_any->fpr ||
            (fpr == best_any->fpr && th < best_any->threshold)) {
            *best_any = sp;
        }
    }
}

static void print_point(const char *label, const SweepPoint *sp, size_t val_count, size_t atk_count)
{
    if (sp->fpr > 1.0) {
        printf("  %s: NOT ACHIEVABLE in swept range\n", label);
        return;
    }
    printf("\n  %s\n", label);
    printf("  Threshold       : %.4f\n", sp->threshold);
    printf("  Validation      : %zu traces (%lu zero-gram)\n", val_count, sp->val.no_grams);
    printf("  Attacks         : %zu traces (%lu zero-gram)\n", atk_count, sp->atk.no_grams);
    printf("  FP=%lu  TN=%lu  TP=%lu  FN=%lu\n",
           sp->val.fp, sp->val.tn, sp->atk.tp, sp->atk.fn);
    printf("  Validation FPR  : %.2f%%\n", sp->fpr * 100);
    printf("  Attack Recall   : %.2f%%\n", sp->recall * 100);
    printf("  Precision       : %.2f%%\n", sp->precision * 100);
    printf("  F1 Score        : %.2f%%\n", sp->f1 * 100);
}

/* ------------------------------------------------------------------ */
/* Per-attack-family report                                           */
/* ------------------------------------------------------------------ */
static void per_family_report(const char *attack_path, const Model *model, double threshold)
{
    DIR *dir = opendir(attack_path);
    if (!dir) return;

    printf("\n  Per-Attack-Family Recall at threshold %.4f:\n", threshold);
    printf("  %-30s %s\n", "Family", "Detected/Total  Recall");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", attack_path, entry->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        TraceList family = {0};
        if (walk_directory(full, (Model *)model, &family, 0) != 0) {
            list_free(&family);
            continue;
        }
        Metrics m = evaluate(&family, threshold, 1);
        double recall = safe_div((double)m.tp, (double)(m.tp + m.fn));
        printf("  %-30s %lu/%-5lu  %.1f%%\n",
               entry->d_name, m.tp, m.tp + m.fn, recall * 100);
        list_free(&family);
    }
    closedir(dir);
}

/* ------------------------------------------------------------------ */
/* Score distribution diagnostic                                       */
/* ------------------------------------------------------------------ */
static void score_distribution(const char *label, const TraceList *traces)
{
    if (traces->count == 0) return;

    /* Compute histogram buckets: 0-5%, 5-10%, 10-20%, 20-50%, 50-100%, exactly 0 */
    unsigned long b_zero = 0, b_lt5 = 0, b_5_10 = 0, b_10_20 = 0, b_20_50 = 0, b_50_100 = 0;
    double sum = 0.0, max_score = 0.0;
    unsigned long zero_gram_count = 0;

    for (size_t i = 0; i < traces->count; i++) {
        const Trace *t = &traces->items[i];
        if (!t->has_grams) { zero_gram_count++; continue; }
        sum += t->score;
        if (t->score > max_score) max_score = t->score;
        if (t->score == 0.0)       b_zero++;
        else if (t->score < 0.05)  b_lt5++;
        else if (t->score < 0.10)  b_5_10++;
        else if (t->score < 0.20)  b_10_20++;
        else if (t->score < 0.50)  b_20_50++;
        else                       b_50_100++;
    }

    size_t scored = traces->count - zero_gram_count;
    double mean = scored > 0 ? sum / scored : 0.0;

    printf("\n  %s Score Distribution (%zu traces, %lu zero-gram):\n",
           label, traces->count, zero_gram_count);
    printf("  Mean score: %.4f  Max score: %.4f\n", mean, max_score);
    printf("  score==0.0  : %lu (%.1f%%)\n", b_zero, 100.0 * b_zero / (scored ? scored : 1));
    printf("  0<score<0.05: %lu (%.1f%%)\n", b_lt5,  100.0 * b_lt5 / (scored ? scored : 1));
    printf("  0.05-0.10   : %lu (%.1f%%)\n", b_5_10, 100.0 * b_5_10 / (scored ? scored : 1));
    printf("  0.10-0.20   : %lu (%.1f%%)\n", b_10_20,100.0 * b_10_20 / (scored ? scored : 1));
    printf("  0.20-0.50   : %lu (%.1f%%)\n", b_20_50,100.0 * b_20_50 / (scored ? scored : 1));
    printf("  0.50-1.00   : %lu (%.1f%%)\n", b_50_100,100.0 * b_50_100 / (scored ? scored : 1));
}

/* ------------------------------------------------------------------ */
/* Run evaluation for a single n-gram size                            */
/* ------------------------------------------------------------------ */
static int run_evaluation(int n, const char *train_path,
                          const char *val_path, const char *attack_path)
{
    printf("\n");
    printf("================================================================\n");
    printf("  %d-GRAM MODEL EVALUATION\n", n);
    printf("================================================================\n");

    Model model = {0};
    TraceList validation = {0}, attacks = {0};

    if (model_init(&model, n) != 0) {
        fprintf(stderr, "Could not allocate %d-gram model\n", n);
        return -1;
    }

    printf("Training on normal traces...\n");
    if (walk_directory(train_path, &model, NULL, 1) != 0) goto fail;
    printf("Unique normal %d-grams: %zu\n", n, model.size);

    printf("Scoring validation traces...\n");
    if (walk_directory(val_path, &model, &validation, 0) != 0) goto fail;
    printf("Validation traces: %zu\n", validation.count);

    printf("Scoring attack traces...\n");
    if (walk_directory(attack_path, &model, &attacks, 0) != 0) goto fail;
    printf("Attack traces: %zu\n", attacks.count);

    /* Score distributions */
    score_distribution("Validation", &validation);
    score_distribution("Attack", &attacks);

    /* Extended threshold sweep: 0.01 to 1.00 in steps of 0.01 */
    printf("\nTHRESHOLD SWEEP (0.01 to 1.00, step 0.01):\n");
    SweepPoint best_5, best_10, best_any;
    run_sweep(&validation, &attacks, 0.01, 1.00, 0.01, &best_5, &best_10, &best_any);

    printf("\n--- SUMMARY ---\n");
    print_point("Best at <=5%% validation FPR", &best_5, validation.count, attacks.count);
    print_point("Best at <=10%% validation FPR", &best_10, validation.count, attacks.count);
    print_point("Lowest achievable FPR", &best_any, validation.count, attacks.count);

    /* Per-family report for the most useful operating point */
    SweepPoint *report_point = NULL;
    if (best_5.fpr <= 1.0) report_point = &best_5;
    else if (best_10.fpr <= 1.0) report_point = &best_10;
    else report_point = &best_any;

    if (report_point->fpr <= 1.0) {
        per_family_report(attack_path, &model, report_point->threshold);
    }

    model_free(&model);
    list_free(&validation);
    list_free(&attacks);
    return 0;

fail:
    model_free(&model);
    list_free(&validation);
    list_free(&attacks);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
    const char *base = "datasets/ADFA-LD/ADFA-LD";
    char train_path[PATH_MAX], val_path[PATH_MAX], attack_path[PATH_MAX];

    snprintf(train_path, sizeof(train_path), "%s/Training_Data_Master", base);
    snprintf(val_path, sizeof(val_path), "%s/Validation_Data_Master", base);
    snprintf(attack_path, sizeof(attack_path), "%s/Attack_Data_Master", base);

    printf("ADFA-LD Unified Model Evaluation\n");
    printf("================================\n");
    printf("Training data  : %s\n", train_path);
    printf("Validation data: %s\n", val_path);
    printf("Attack data    : %s\n", attack_path);
    printf("Scoring method : unseen_ngram_ratio = unseen / total\n");
    printf("Threshold rule : selected from validation only (no attack peeking)\n");
    printf("Empty traces   : treated as NOT anomalous (score=0)\n");

    int rc = 0;
    if (run_evaluation(3, train_path, val_path, attack_path) != 0) rc = 1;
    if (run_evaluation(4, train_path, val_path, attack_path) != 0) rc = 1;

    printf("\n================================================================\n");
    printf("  EVALUATION COMPLETE\n");
    printf("================================================================\n");

    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
