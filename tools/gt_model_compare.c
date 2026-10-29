/*
 * gt_model_compare.c — Ground-Truth Model Comparison Tool (Stage 19)
 *
 * Evaluates two models (A and B) against the same ground-truth manifest
 * and dataset. Compares precision, recall, F1, FPR, alert rate, and
 * detection latency.
 *
 * Usage:
 *   ./tools/gt_model_compare \
 *       --model-a baseline_model.dat \
 *       --model-b experimental_normal_only_model.dat \
 *       --manifest gt_manifest.json \
 *       --dataset gt_eval_dataset.csv
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "model.h"
#include "anomaly.h"
#include "ngram.h"

/* -----------------------------------------------------------------------
 * Shared structures (same as gt_evaluate.c)
 * ----------------------------------------------------------------------- */
#define MAX_WORKLOADS 128

typedef struct {
    char workload_id[64];
    char workload_type[32];
    char ground_truth_label[32];
    uint32_t pid;
    uint64_t start_timestamp_ns;
    uint64_t end_timestamp_ns;
    char description[256];
} ManifestWorkload;

typedef struct {
    int schema_version;
    ManifestWorkload workloads[MAX_WORKLOADS];
    int workload_count;
} Manifest;

typedef struct {
    uint64_t timestamp_ns;
    uint32_t pid;
    int s1, s2, s3;
    int matched_workload;
} CSVEvent;

typedef struct {
    unsigned long tp, fp, tn, fn;
    double precision, recall, f1_score, fpr, fnr;
} EvalMetrics;

/* -----------------------------------------------------------------------
 * JSON helpers
 * ----------------------------------------------------------------------- */
static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int json_str(const char *p, const char *key, char *out, size_t sz)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *f = strstr(p, search);
    if (!f) return -1;
    f += strlen(search);
    f = skip_ws(f);
    if (*f != ':') return -1;
    f = skip_ws(f + 1);
    if (*f != '"') return -1;
    f++;
    const char *q = strchr(f, '"');
    if (!q) return -1;
    size_t len = (size_t)(q - f);
    if (len >= sz) len = sz - 1;
    memcpy(out, f, len);
    out[len] = '\0';
    return 0;
}

static int json_u64(const char *p, const char *key, uint64_t *out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *f = strstr(p, search);
    if (!f) return -1;
    f += strlen(search);
    f = skip_ws(f);
    if (*f != ':') return -1;
    f = skip_ws(f + 1);
    char *endp;
    *out = strtoull(f, &endp, 10);
    return (endp == f) ? -1 : 0;
}

/* -----------------------------------------------------------------------
 * Parse manifest
 * ----------------------------------------------------------------------- */
static int parse_manifest(const char *path, Manifest *m)
{
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Error: Cannot open manifest: %s\n", path); return -1; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    buf[sz] = '\0';
    fclose(f);

    memset(m, 0, sizeof(*m));

    const char *arr = strstr(buf, "\"workloads\"");
    if (!arr) { free(buf); return -1; }
    arr = strchr(arr, '[');
    if (!arr) { free(buf); return -1; }
    arr++;

    m->workload_count = 0;
    while (m->workload_count < MAX_WORKLOADS)
    {
        const char *obj = strchr(arr, '{');
        if (!obj) break;
        const char *obj_e = strchr(obj, '}');
        if (!obj_e) break;
        size_t olen = (size_t)(obj_e - obj + 1);
        char *o = malloc(olen + 1);
        memcpy(o, obj, olen);
        o[olen] = '\0';

        ManifestWorkload *w = &m->workloads[m->workload_count];
        memset(w, 0, sizeof(*w));
        json_str(o, "workload_id", w->workload_id, sizeof(w->workload_id));
        json_str(o, "workload_type", w->workload_type, sizeof(w->workload_type));
        json_str(o, "ground_truth_label", w->ground_truth_label, sizeof(w->ground_truth_label));
        uint64_t pid_val = 0;
        json_u64(o, "pid", &pid_val);
        w->pid = (uint32_t)pid_val;
        json_u64(o, "start_timestamp_ns", &w->start_timestamp_ns);
        json_u64(o, "end_timestamp_ns", &w->end_timestamp_ns);
        json_str(o, "description", w->description, sizeof(w->description));
        free(o);
        m->workload_count++;
        arr = obj_e + 1;
    }

    free(buf);
    return 0;
}

/* -----------------------------------------------------------------------
 * Parse CSV header
 * ----------------------------------------------------------------------- */
static void parse_csv_hdr(const char *line, int *col_ts, int *col_pid,
                           int *col_s1, int *col_s2, int *col_s3)
{
    char hdr[1024];
    strncpy(hdr, line, sizeof(hdr) - 1);
    hdr[sizeof(hdr) - 1] = '\0';
    char *nl = strchr(hdr, '\n');
    if (nl) *nl = '\0';

    *col_ts = -1; *col_pid = -1;
    *col_s1 = -1; *col_s2 = -1; *col_s3 = -1;

    char *tok, *rest = hdr;
    int c = 0;
    while ((tok = strtok_r(rest, ",", &rest)) != NULL)
    {
        c++;
        while (*tok == ' ' || *tok == '"') tok++;
        size_t tl = strlen(tok);
        while (tl > 0 && (tok[tl-1] == ' ' || tok[tl-1] == '"' || tok[tl-1] == '\r'))
            tok[--tl] = '\0';
        if      (strcmp(tok, "monotonic_timestamp_ns") == 0) *col_ts  = c;
        else if (strcmp(tok, "pid") == 0)                    *col_pid = c;
        else if (strcmp(tok, "syscall_1") == 0)              *col_s1  = c;
        else if (strcmp(tok, "syscall_2") == 0)              *col_s2  = c;
        else if (strcmp(tok, "syscall_3") == 0)              *col_s3  = c;
    }
    if (*col_ts  < 0) *col_ts  = 1;
    if (*col_pid < 0) *col_pid = 2;
    if (*col_s1  < 0) *col_s1  = 4;
    if (*col_s2  < 0) *col_s2  = 5;
    if (*col_s3  < 0) *col_s3  = 6;
}

/* -----------------------------------------------------------------------
 * Load CSV
 * ----------------------------------------------------------------------- */
static int load_events(const char *path, CSVEvent **out, size_t *cnt)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }
    int ct, cp, c1, c2, c3;
    parse_csv_hdr(line, &ct, &cp, &c1, &c2, &c3);

    size_t cap = 8192, n = 0;
    CSVEvent *ev = malloc(cap * sizeof(CSVEvent));
    if (!ev) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns")) continue;
        char buf[1024];
        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *tok, *rest = buf;
        int col = 0;
        CSVEvent e;
        memset(&e, 0, sizeof(e));
        e.s1 = -1; e.s2 = -1; e.s3 = -1;
        e.matched_workload = -1;
        while ((tok = strtok_r(rest, ",", &rest)) != NULL)
        {
            col++;
            while (*tok == '"' || *tok == ' ') tok++;
            size_t tl = strlen(tok);
            while (tl > 0 && (tok[tl-1] == '"' || tok[tl-1] == '\n' || tok[tl-1] == '\r'))
                tok[--tl] = '\0';
            if      (col == ct) e.timestamp_ns = strtoull(tok, NULL, 10);
            else if (col == cp) e.pid = (uint32_t)strtoul(tok, NULL, 10);
            else if (col == c1) e.s1 = atoi(tok);
            else if (col == c2) e.s2 = atoi(tok);
            else if (col == c3) e.s3 = atoi(tok);
        }
        if (e.s1 < 0 || e.s2 < 0 || e.s3 < 0) continue;
        if (n >= cap) {
            cap *= 2;
            CSVEvent *tmp = realloc(ev, cap * sizeof(CSVEvent));
            if (!tmp) { free(ev); fclose(f); return -1; }
            ev = tmp;
        }
        ev[n++] = e;
    }
    fclose(f);
    *out = ev;
    *cnt = n;
    return 0;
}

/* -----------------------------------------------------------------------
 * Match events to workloads
 * ----------------------------------------------------------------------- */
static void match_events(CSVEvent *ev, size_t n, const Manifest *m)
{
    for (size_t i = 0; i < n; i++)
    {
        ev[i].matched_workload = -1;
        for (int w = 0; w < m->workload_count; w++)
        {
            if (ev[i].pid == m->workloads[w].pid &&
                ev[i].timestamp_ns >= m->workloads[w].start_timestamp_ns &&
                ev[i].timestamp_ns <= m->workloads[w].end_timestamp_ns)
            {
                ev[i].matched_workload = w;
                break;
            }
        }
        if (ev[i].matched_workload < 0)
        {
            for (int w = 0; w < m->workload_count; w++)
            {
                if (ev[i].timestamp_ns >= m->workloads[w].start_timestamp_ns &&
                    ev[i].timestamp_ns <= m->workloads[w].end_timestamp_ns)
                {
                    ev[i].matched_workload = w;
                    break;
                }
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Compute workload-level metrics for a model
 * ----------------------------------------------------------------------- */
static void compute_workload_metrics(const CSVEvent *ev, size_t n,
                                      const Manifest *manifest,
                                      const NormalModel *model,
                                      EvalMetrics *out,
                                      unsigned long *alert_count_out,
                                      unsigned long *total_matched_out)
{
    int has_alert[MAX_WORKLOADS] = {0};
    int has_events[MAX_WORKLOADS] = {0};
    unsigned long alerts = 0, matched = 0;

    for (size_t i = 0; i < n; i++)
    {
        int w = ev[i].matched_workload;
        if (w < 0) continue;
        has_events[w] = 1;
        matched++;

        NGram ngram = {{ev[i].s1, ev[i].s2, ev[i].s3}};
        double score = anomaly_score(model, &ngram);
        if (anomaly_is_suspicious(score))
        {
            has_alert[w] = 1;
            alerts++;
        }
    }

    unsigned long tp = 0, fp = 0, tn = 0, fn = 0;
    for (int w = 0; w < manifest->workload_count; w++)
    {
        if (!has_events[w]) continue;
        int gt = (strcmp(manifest->workloads[w].ground_truth_label, "suspicious") == 0);
        int pred = has_alert[w];
        if (gt && pred) tp++;
        else if (!gt && pred) fp++;
        else if (!gt && !pred) tn++;
        else fn++;
    }

    out->tp = tp; out->fp = fp; out->tn = tn; out->fn = fn;

    out->precision = (tp + fp > 0) ? (double)tp / (tp + fp) : 0.0;
    out->recall    = (tp + fn > 0) ? (double)tp / (tp + fn) : 0.0;
    out->f1_score  = (out->precision + out->recall > 0)
                     ? 2.0 * out->precision * out->recall / (out->precision + out->recall) : 0.0;
    out->fpr       = (fp + tn > 0) ? (double)fp / (fp + tn) : 0.0;
    out->fnr       = (fn + tp > 0) ? (double)fn / (fn + tp) : 0.0;

    *alert_count_out = alerts;
    *total_matched_out = matched;
}

/* -----------------------------------------------------------------------
 * Compute 3-gram level metrics for a model
 * ----------------------------------------------------------------------- */
static void compute_ngram_metrics(const CSVEvent *ev, size_t n,
                                  const Manifest *manifest,
                                  const NormalModel *model,
                                  EvalMetrics *out)
{
    unsigned long tp = 0, fp = 0, tn = 0, fn = 0;

    for (size_t i = 0; i < n; i++)
    {
        int w = ev[i].matched_workload;
        if (w < 0) continue;

        int gt = (strcmp(manifest->workloads[w].ground_truth_label, "suspicious") == 0);
        NGram ngram = {{ev[i].s1, ev[i].s2, ev[i].s3}};
        double score = anomaly_score(model, &ngram);
        int pred = anomaly_is_suspicious(score);

        if (gt && pred) tp++;
        else if (!gt && pred) fp++;
        else if (!gt && !pred) tn++;
        else fn++;
    }

    out->tp = tp; out->fp = fp; out->tn = tn; out->fn = fn;
    out->precision = (tp + fp > 0) ? (double)tp / (tp + fp) : 0.0;
    out->recall    = (tp + fn > 0) ? (double)tp / (tp + fn) : 0.0;
    out->f1_score  = (out->precision + out->recall > 0)
                     ? 2.0 * out->precision * out->recall / (out->precision + out->recall) : 0.0;
    out->fpr       = (fp + tn > 0) ? (double)fp / (fp + tn) : 0.0;
    out->fnr       = (fn + tp > 0) ? (double)fn / (fn + tp) : 0.0;
}

/* -----------------------------------------------------------------------
 * Compute mean detection latency for suspicious workloads
 * ----------------------------------------------------------------------- */
static double compute_mean_latency(const CSVEvent *ev, size_t n,
                                    const Manifest *manifest,
                                    const NormalModel *model)
{
    double total_latency = 0.0;
    int count = 0;

    for (int w = 0; w < manifest->workload_count; w++)
    {
        if (strcmp(manifest->workloads[w].ground_truth_label, "suspicious") != 0)
            continue;

        uint64_t first_alert = UINT64_MAX;
        for (size_t i = 0; i < n; i++)
        {
            if (ev[i].matched_workload != w) continue;
            NGram ngram = {{ev[i].s1, ev[i].s2, ev[i].s3}};
            double score = anomaly_score(model, &ngram);
            if (anomaly_is_suspicious(score) && ev[i].timestamp_ns < first_alert)
                first_alert = ev[i].timestamp_ns;
        }

        if (first_alert < UINT64_MAX)
        {
            double latency_ms = (double)(first_alert - manifest->workloads[w].start_timestamp_ns) / 1e6;
            total_latency += latency_ms;
            count++;
        }
    }

    return (count > 0) ? total_latency / count : -1.0;
}

/* -----------------------------------------------------------------------
 * Print usage
 * ----------------------------------------------------------------------- */
static void print_usage(const char *prog)
{
    printf("Usage: %s --model-a <a.dat> --model-b <b.dat> --manifest <m.json> --dataset <d.csv>\n", prog);
}

int main(int argc, char **argv)
{
    const char *model_a_path = NULL, *model_b_path = NULL;
    const char *manifest_path = NULL, *dataset_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--model-a") == 0 && i + 1 < argc) model_a_path = argv[++i];
        else if (strcmp(argv[i], "--model-b") == 0 && i + 1 < argc) model_b_path = argv[++i];
        else if (strcmp(argv[i], "--manifest") == 0 && i + 1 < argc) manifest_path = argv[++i];
        else if (strcmp(argv[i], "--dataset") == 0 && i + 1 < argc) dataset_path = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        { print_usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown: %s\n", argv[i]); return 1; }
    }

    if (!model_a_path || !model_b_path || !manifest_path || !dataset_path)
    {
        fprintf(stderr, "Error: All four arguments required\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Ground-Truth Model Comparison (Stage 19)\n");
    printf("=========================================\n");
    printf("Model A   : %s\n", model_a_path);
    printf("Model B   : %s\n", model_b_path);
    printf("Manifest  : %s\n", manifest_path);
    printf("Dataset   : %s\n", dataset_path);
    printf("Threshold : %.2f\n\n", ANOMALY_THRESHOLD);

    NormalModel model_a, model_b;
    if (normal_model_load(&model_a, model_a_path) != 0)
    { fprintf(stderr, "Error: Cannot load Model A\n"); return 1; }
    if (normal_model_load(&model_b, model_b_path) != 0)
    { fprintf(stderr, "Error: Cannot load Model B\n"); return 1; }

    struct stat sa, sb;
    long sz_a = (stat(model_a_path, &sa) == 0) ? (long)sa.st_size : -1;
    long sz_b = (stat(model_b_path, &sb) == 0) ? (long)sb.st_size : -1;

    Manifest manifest;
    if (parse_manifest(manifest_path, &manifest) != 0) return 1;

    CSVEvent *events = NULL;
    size_t event_count = 0;
    if (load_events(dataset_path, &events, &event_count) != 0) return 1;

    match_events(events, event_count, &manifest);

    printf("Events loaded  : %zu\n", event_count);
    printf("Workloads      : %d\n\n", manifest.workload_count);

    EvalMetrics m_a, m_b;
    unsigned long alerts_a, alerts_b, matched_a, matched_b;

    compute_workload_metrics(events, event_count, &manifest, &model_a,
                             &m_a, &alerts_a, &matched_a);
    compute_workload_metrics(events, event_count, &manifest, &model_b,
                             &m_b, &alerts_b, &matched_b);

    double lat_a = compute_mean_latency(events, event_count, &manifest, &model_a);
    double lat_b = compute_mean_latency(events, event_count, &manifest, &model_b);

    double rate_a = (matched_a > 0) ? (double)alerts_a / matched_a * 100.0 : 0.0;
    double rate_b = (matched_b > 0) ? (double)alerts_b / matched_b * 100.0 : 0.0;

    EvalMetrics ng_a, ng_b;
    compute_ngram_metrics(events, event_count, &manifest, &model_a, &ng_a);
    compute_ngram_metrics(events, event_count, &manifest, &model_b, &ng_b);

    /* Print comparison table */
    printf("Comparison Table (Per-Workload Level)\n");
    printf("=====================================\n\n");

    printf("%-30s | %-20s | %-20s\n", "Metric", "Model A", "Model B");
    printf("%-30s-+-%-20s-+-%-20s\n",
           "------------------------------", "--------------------", "--------------------");

    printf("%-30s | %-20zu | %-20zu\n", "Unique 3-grams",
           model_a.size, model_b.size);
    printf("%-30s | %-20lu | %-20lu\n", "Total training 3-grams",
           model_a.total_ngrams, model_b.total_ngrams);

    char buf[2][32];
    snprintf(buf[0], 32, "%ld bytes", sz_a);
    snprintf(buf[1], 32, "%ld bytes", sz_b);
    printf("%-30s | %-20s | %-20s\n", "Model file size", buf[0], buf[1]);

    printf("%-30s | %-20lu | %-20lu\n", "Matched events", matched_a, matched_b);

    snprintf(buf[0], 32, "%.4f%%", rate_a);
    snprintf(buf[1], 32, "%.4f%%", rate_b);
    printf("%-30s | %-20s | %-20s\n", "3-gram alert rate", buf[0], buf[1]);

    printf("%-30s | %-20lu | %-20lu\n", "True Positives (TP)", m_a.tp, m_b.tp);
    printf("%-30s | %-20lu | %-20lu\n", "False Positives (FP)", m_a.fp, m_b.fp);
    printf("%-30s | %-20lu | %-20lu\n", "True Negatives (TN)", m_a.tn, m_b.tn);
    printf("%-30s | %-20lu | %-20lu\n", "False Negatives (FN)", m_a.fn, m_b.fn);

    snprintf(buf[0], 32, "%.4f", m_a.precision);
    snprintf(buf[1], 32, "%.4f", m_b.precision);
    printf("%-30s | %-20s | %-20s\n", "Precision", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", m_a.recall);
    snprintf(buf[1], 32, "%.4f", m_b.recall);
    printf("%-30s | %-20s | %-20s\n", "Recall", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", m_a.f1_score);
    snprintf(buf[1], 32, "%.4f", m_b.f1_score);
    printf("%-30s | %-20s | %-20s\n", "F1-Score", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", m_a.fpr);
    snprintf(buf[1], 32, "%.4f", m_b.fpr);
    printf("%-30s | %-20s | %-20s\n", "False Positive Rate (FPR)", buf[0], buf[1]);

    if (lat_a >= 0) snprintf(buf[0], 32, "%.2f ms", lat_a);
    else            snprintf(buf[0], 32, "N/A");
    if (lat_b >= 0) snprintf(buf[1], 32, "%.2f ms", lat_b);
    else            snprintf(buf[1], 32, "N/A");
    printf("%-30s | %-20s | %-20s\n", "Mean detection latency", buf[0], buf[1]);

    /* Print Per-3-Gram comparison table */
    printf("\nComparison Table (Per-3-Gram Level)\n");
    printf("===================================\n\n");

    printf("%-30s | %-20s | %-20s\n", "Metric", "Model A", "Model B");
    printf("%-30s-+-%-20s-+-%-20s\n",
           "------------------------------", "--------------------", "--------------------");
    printf("%-30s | %-20lu | %-20lu\n", "True Positives (TP)", ng_a.tp, ng_b.tp);
    printf("%-30s | %-20lu | %-20lu\n", "False Positives (FP)", ng_a.fp, ng_b.fp);
    printf("%-30s | %-20lu | %-20lu\n", "True Negatives (TN)", ng_a.tn, ng_b.tn);
    printf("%-30s | %-20lu | %-20lu\n", "False Negatives (FN)", ng_a.fn, ng_b.fn);

    snprintf(buf[0], 32, "%.4f", ng_a.precision);
    snprintf(buf[1], 32, "%.4f", ng_b.precision);
    printf("%-30s | %-20s | %-20s\n", "Precision", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", ng_a.recall);
    snprintf(buf[1], 32, "%.4f", ng_b.recall);
    printf("%-30s | %-20s | %-20s\n", "Recall", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", ng_a.f1_score);
    snprintf(buf[1], 32, "%.4f", ng_b.f1_score);
    printf("%-30s | %-20s | %-20s\n", "F1-Score", buf[0], buf[1]);

    snprintf(buf[0], 32, "%.4f", ng_a.fpr);
    snprintf(buf[1], 32, "%.4f", ng_b.fpr);
    printf("%-30s | %-20s | %-20s\n", "False Positive Rate (FPR)", buf[0], buf[1]);

    printf("\nBoth models evaluated on exactly %d workloads (%zu events).\n",
           manifest.workload_count, event_count);
    printf("Ground-truth labels from manifest — NOT from detector predictions.\n");

    free(events);
    return 0;
}
