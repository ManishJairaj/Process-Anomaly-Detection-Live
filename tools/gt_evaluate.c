/*
 * gt_evaluate.c — Ground-Truth Evaluation Tool (Stage 19)
 *
 * Evaluates the syscall 3-gram anomaly detector against independently
 * labelled ground-truth workloads recorded in a manifest JSON.
 *
 * Three evaluation levels:
 *   1. Per-3-gram:    Each CSV row is one 3-gram event.
 *   2. Per-process:   Aggregate by PID — process is anomalous if ANY
 *                     of its 3-grams exceeded the threshold.
 *   3. Per-workload:  Aggregate by manifest workload_id — workload
 *                     is anomalous if ANY of its matched events
 *                     exceeded the threshold.
 *
 * Metrics: TP, FP, TN, FN, Precision, Recall, F1, FPR, FNR,
 *          Confusion Matrix, Detection Latency.
 *
 * Usage:
 *   ./tools/gt_evaluate --manifest gt_manifest.json \
 *                       --dataset gt_eval_dataset.csv \
 *                       --model baseline_model.dat
 *
 * The manifest supplies ground-truth labels and timestamp windows.
 * The dataset supplies scored 3-gram events.
 * The model is loaded for re-scoring (to ensure consistency).
 *
 * IMPORTANT: The ground-truth label comes from the manifest, NOT from
 * the predicted_label column in the CSV. These are deliberately separate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>

#include "model.h"
#include "anomaly.h"
#include "ngram.h"

/* -----------------------------------------------------------------------
 * Ground-truth manifest structures
 * ----------------------------------------------------------------------- */
#define MAX_WORKLOADS 128
#define MAX_EVENTS 500000

typedef struct {
    char workload_id[64];
    char workload_type[32];    /* "benign" or "security_relevant" */
    char ground_truth_label[32]; /* "benign" or "suspicious" */
    uint32_t pid;
    uint64_t start_timestamp_ns;
    uint64_t end_timestamp_ns;
    char description[256];
    char dataset_filename[256];
    char host_arch[32];
    char kernel_version[64];
} ManifestWorkload;

typedef struct {
    int schema_version;
    char model_file[256];
    char timestamp_type[32];
    ManifestWorkload workloads[MAX_WORKLOADS];
    int workload_count;
} Manifest;

/* -----------------------------------------------------------------------
 * Parsed CSV event
 * ----------------------------------------------------------------------- */
typedef struct {
    uint64_t timestamp_ns;
    uint32_t pid;
    int s1, s2, s3;
    double anomaly_score;   /* from CSV (detector's original score) */
    char predicted_label[32];
    /* Re-scored values */
    double rescore;
    int rescore_suspicious;
    /* Ground-truth assignment */
    int matched_workload;   /* index into manifest, or -1 */
} CSVEvent;

/* -----------------------------------------------------------------------
 * Evaluation metrics
 * ----------------------------------------------------------------------- */
typedef struct {
    unsigned long tp, fp, tn, fn;
} ConfusionMatrix;

typedef struct {
    ConfusionMatrix cm;
    double precision;
    double recall;
    double f1_score;
    double fpr;     /* false positive rate: FP / (FP + TN) */
    double fnr;     /* false negative rate: FN / (FN + TP) */
} EvalMetrics;

/* -----------------------------------------------------------------------
 * Detection latency record
 * ----------------------------------------------------------------------- */
typedef struct {
    char workload_id[64];
    char ground_truth_label[32];
    uint64_t workload_start_ns;
    uint64_t first_event_ns;       /* first syscall event in window */
    uint64_t first_alert_ns;       /* first anomaly alert (score >= threshold) */
    int has_events;
    int has_alert;
} LatencyRecord;

/* -----------------------------------------------------------------------
 * JSON parser helpers (minimal, no external dependencies)
 * ----------------------------------------------------------------------- */
static const char *skip_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int parse_json_string(const char *p, const char *key, char *out, size_t out_size, const char **end)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *f = strstr(p, search);
    if (!f) return -1;

    f += strlen(search);
    f = skip_ws(f);
    if (*f != ':') return -1;
    f++;
    f = skip_ws(f);
    if (*f != '"') return -1;
    f++;

    const char *q = strchr(f, '"');
    if (!q) return -1;

    size_t len = (size_t)(q - f);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, f, len);
    out[len] = '\0';

    if (end) *end = q + 1;
    return 0;
}

static int parse_json_uint64(const char *p, const char *key, uint64_t *out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *f = strstr(p, search);
    if (!f) return -1;

    f += strlen(search);
    f = skip_ws(f);
    if (*f != ':') return -1;
    f++;
    f = skip_ws(f);

    char *endp;
    unsigned long long val = strtoull(f, &endp, 10);
    if (endp == f) return -1;
    *out = (uint64_t)val;
    return 0;
}

static int parse_json_int(const char *p, const char *key, int *out)
{
    uint64_t v;
    if (parse_json_uint64(p, key, &v) != 0) return -1;
    *out = (int)v;
    return 0;
}

/* -----------------------------------------------------------------------
 * Parse manifest JSON
 * ----------------------------------------------------------------------- */
static int parse_manifest(const char *path, Manifest *manifest)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, "Error: Cannot open manifest: %s\n", path);
        return -1;
    }

    /* Read entire file */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)fsize, f) != (size_t)fsize)
    {
        free(buf); fclose(f); return -1;
    }
    buf[fsize] = '\0';
    fclose(f);

    memset(manifest, 0, sizeof(*manifest));
    parse_json_int(buf, "schema_version", &manifest->schema_version);
    parse_json_string(buf, "model_file", manifest->model_file, sizeof(manifest->model_file), NULL);
    parse_json_string(buf, "timestamp_type", manifest->timestamp_type, sizeof(manifest->timestamp_type), NULL);

    /* Parse workloads array */
    const char *arr = strstr(buf, "\"workloads\"");
    if (!arr) { free(buf); return -1; }

    /* Find array start */
    arr = strchr(arr, '[');
    if (!arr) { free(buf); return -1; }
    arr++;

    manifest->workload_count = 0;

    while (manifest->workload_count < MAX_WORKLOADS)
    {
        /* Find next object */
        const char *obj_start = strchr(arr, '{');
        if (!obj_start) break;

        const char *obj_end = strchr(obj_start, '}');
        if (!obj_end) break;

        /* Extract object as substring */
        size_t obj_len = (size_t)(obj_end - obj_start + 1);
        char *obj = malloc(obj_len + 1);
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        ManifestWorkload *w = &manifest->workloads[manifest->workload_count];
        memset(w, 0, sizeof(*w));

        parse_json_string(obj, "workload_id", w->workload_id, sizeof(w->workload_id), NULL);
        parse_json_string(obj, "workload_type", w->workload_type, sizeof(w->workload_type), NULL);
        parse_json_string(obj, "ground_truth_label", w->ground_truth_label, sizeof(w->ground_truth_label), NULL);

        uint64_t pid_val = 0;
        parse_json_uint64(obj, "pid", &pid_val);
        w->pid = (uint32_t)pid_val;

        parse_json_uint64(obj, "start_timestamp_ns", &w->start_timestamp_ns);
        parse_json_uint64(obj, "end_timestamp_ns", &w->end_timestamp_ns);

        parse_json_string(obj, "description", w->description, sizeof(w->description), NULL);
        parse_json_string(obj, "dataset_filename", w->dataset_filename, sizeof(w->dataset_filename), NULL);
        parse_json_string(obj, "host_arch", w->host_arch, sizeof(w->host_arch), NULL);
        parse_json_string(obj, "kernel_version", w->kernel_version, sizeof(w->kernel_version), NULL);

        free(obj);
        manifest->workload_count++;
        arr = obj_end + 1;
    }

    free(buf);
    return 0;
}

/* -----------------------------------------------------------------------
 * Parse CSV header for column indices
 * ----------------------------------------------------------------------- */
static void parse_csv_header(const char *header_line,
                              int *col_ts, int *col_pid, int *col_s1,
                              int *col_s2, int *col_s3, int *col_score,
                              int *col_label)
{
    char hdr_buf[1024];
    strncpy(hdr_buf, header_line, sizeof(hdr_buf) - 1);
    hdr_buf[sizeof(hdr_buf) - 1] = '\0';

    char *nl = strchr(hdr_buf, '\n');
    if (nl) *nl = '\0';

    *col_ts = -1; *col_pid = -1;
    *col_s1 = -1; *col_s2 = -1; *col_s3 = -1;
    *col_score = -1; *col_label = -1;

    char *tok, *rest = hdr_buf;
    int cidx = 0;
    while ((tok = strtok_r(rest, ",", &rest)) != NULL)
    {
        cidx++;
        while (*tok == ' ' || *tok == '"') tok++;
        size_t tlen = strlen(tok);
        while (tlen > 0 && (tok[tlen-1] == ' ' || tok[tlen-1] == '"' ||
                            tok[tlen-1] == '\r'))
            tok[--tlen] = '\0';

        if      (strcmp(tok, "monotonic_timestamp_ns") == 0) *col_ts    = cidx;
        else if (strcmp(tok, "pid") == 0)                    *col_pid   = cidx;
        else if (strcmp(tok, "syscall_1") == 0)              *col_s1    = cidx;
        else if (strcmp(tok, "syscall_2") == 0)              *col_s2    = cidx;
        else if (strcmp(tok, "syscall_3") == 0)              *col_s3    = cidx;
        else if (strcmp(tok, "anomaly_score") == 0)          *col_score = cidx;
        else if (strcmp(tok, "predicted_label") == 0)        *col_label = cidx;
    }

    /* Fallbacks */
    if (*col_ts    < 0) *col_ts    = 1;
    if (*col_pid   < 0) *col_pid   = 2;
    if (*col_s1    < 0) *col_s1    = 4;
    if (*col_s2    < 0) *col_s2    = 5;
    if (*col_s3    < 0) *col_s3    = 6;
    if (*col_score < 0) *col_score = 7;
    if (*col_label < 0) *col_label = 8;
}

/* -----------------------------------------------------------------------
 * Load CSV events
 * ----------------------------------------------------------------------- */
static int load_csv_events(const char *path, CSVEvent **events_out,
                            size_t *count_out)
{
    FILE *f = fopen(path, "r");
    if (!f)
    {
        fprintf(stderr, "Error: Cannot open dataset CSV: %s\n", path);
        return -1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), f))
    {
        fprintf(stderr, "Error: Empty CSV: %s\n", path);
        fclose(f);
        return -1;
    }

    int col_ts, col_pid, col_s1, col_s2, col_s3, col_score, col_label;
    parse_csv_header(line, &col_ts, &col_pid, &col_s1, &col_s2, &col_s3,
                     &col_score, &col_label);

    size_t cap = 8192;
    size_t count = 0;
    CSVEvent *events = malloc(cap * sizeof(CSVEvent));
    if (!events) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
            continue;

        char buf[1024];
        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *tok, *rest = buf;
        int col = 0;
        CSVEvent ev;
        memset(&ev, 0, sizeof(ev));
        ev.s1 = -1; ev.s2 = -1; ev.s3 = -1;
        ev.matched_workload = -1;

        char label_buf[32] = "";

        while ((tok = strtok_r(rest, ",", &rest)) != NULL)
        {
            col++;
            /* Strip quotes */
            while (*tok == '"' || *tok == ' ') tok++;
            size_t tlen = strlen(tok);
            while (tlen > 0 && (tok[tlen-1] == '"' || tok[tlen-1] == '\n' ||
                                tok[tlen-1] == '\r' || tok[tlen-1] == ' '))
                tok[--tlen] = '\0';

            if      (col == col_ts)    ev.timestamp_ns = strtoull(tok, NULL, 10);
            else if (col == col_pid)   ev.pid = (uint32_t)strtoul(tok, NULL, 10);
            else if (col == col_s1)    ev.s1 = atoi(tok);
            else if (col == col_s2)    ev.s2 = atoi(tok);
            else if (col == col_s3)    ev.s3 = atoi(tok);
            else if (col == col_score) ev.anomaly_score = atof(tok);
            else if (col == col_label) {
                strncpy(label_buf, tok, sizeof(label_buf) - 1);
                label_buf[sizeof(label_buf) - 1] = '\0';
            }
        }

        if (ev.s1 < 0 || ev.s2 < 0 || ev.s3 < 0)
            continue;

        snprintf(ev.predicted_label, sizeof(ev.predicted_label), "%s", label_buf);

        if (count >= cap)
        {
            cap *= 2;
            CSVEvent *tmp = realloc(events, cap * sizeof(CSVEvent));
            if (!tmp) { free(events); fclose(f); return -1; }
            events = tmp;
        }

        events[count++] = ev;
    }

    fclose(f);
    *events_out = events;
    *count_out = count;
    return 0;
}

/* -----------------------------------------------------------------------
 * Match events to workloads using PID + timestamp window
 *
 * NOTE: eBPF events use monotonic timestamps. The manifest also uses
 * monotonic timestamps. We match events to the workload whose child
 * process PID and time window contain the event.
 *
 * However, workloads spawn subprocesses via bash -c, so the actual
 * syscall PIDs may be children of the recorded PID. We use a generous
 * timestamp window match: if an event's timestamp falls within a
 * workload's [start, end] window, it's considered potentially part
 * of that workload. PID matching is preferred when possible but
 * timestamp-only matching is a fallback for child processes.
 * ----------------------------------------------------------------------- */
static void match_events_to_workloads(CSVEvent *events, size_t event_count,
                                       const Manifest *manifest)
{
    for (size_t i = 0; i < event_count; i++)
    {
        events[i].matched_workload = -1;

        /* First pass: exact PID + timestamp match */
        for (int w = 0; w < manifest->workload_count; w++)
        {
            const ManifestWorkload *wl = &manifest->workloads[w];
            if (events[i].pid == wl->pid &&
                events[i].timestamp_ns >= wl->start_timestamp_ns &&
                events[i].timestamp_ns <= wl->end_timestamp_ns)
            {
                events[i].matched_workload = w;
                break;
            }
        }

        /* Second pass: timestamp-only match (for child processes) */
        if (events[i].matched_workload < 0)
        {
            for (int w = 0; w < manifest->workload_count; w++)
            {
                const ManifestWorkload *wl = &manifest->workloads[w];
                if (events[i].timestamp_ns >= wl->start_timestamp_ns &&
                    events[i].timestamp_ns <= wl->end_timestamp_ns)
                {
                    events[i].matched_workload = w;
                    break;
                }
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Re-score events using the loaded model
 * ----------------------------------------------------------------------- */
static void rescore_events(CSVEvent *events, size_t count,
                            const NormalModel *model)
{
    for (size_t i = 0; i < count; i++)
    {
        NGram ngram = {{events[i].s1, events[i].s2, events[i].s3}};
        events[i].rescore = anomaly_score(model, &ngram);
        events[i].rescore_suspicious = anomaly_is_suspicious(events[i].rescore);
    }
}

/* -----------------------------------------------------------------------
 * Compute evaluation metrics from confusion matrix
 * ----------------------------------------------------------------------- */
static void compute_metrics(const ConfusionMatrix *cm, EvalMetrics *m)
{
    m->cm = *cm;

    /* Precision = TP / (TP + FP) */
    if (cm->tp + cm->fp > 0)
        m->precision = (double)cm->tp / (double)(cm->tp + cm->fp);
    else
        m->precision = 0.0;

    /* Recall = TP / (TP + FN) */
    if (cm->tp + cm->fn > 0)
        m->recall = (double)cm->tp / (double)(cm->tp + cm->fn);
    else
        m->recall = 0.0;

    /* F1 = 2 * P * R / (P + R) */
    if (m->precision + m->recall > 0.0)
        m->f1_score = 2.0 * m->precision * m->recall / (m->precision + m->recall);
    else
        m->f1_score = 0.0;

    /* FPR = FP / (FP + TN) */
    if (cm->fp + cm->tn > 0)
        m->fpr = (double)cm->fp / (double)(cm->fp + cm->tn);
    else
        m->fpr = 0.0;

    /* FNR = FN / (FN + TP) */
    if (cm->fn + cm->tp > 0)
        m->fnr = (double)cm->fn / (double)(cm->fn + cm->tp);
    else
        m->fnr = 0.0;
}

/* -----------------------------------------------------------------------
 * Print metrics
 * ----------------------------------------------------------------------- */
static void print_metrics(const char *title, const EvalMetrics *m)
{
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("=");
    printf("\n");

    printf("Confusion Matrix:\n");
    printf("                  Predicted Anomalous  Predicted Normal\n");
    printf("  Actual Susp.    TP = %-15lu  FN = %-15lu\n", m->cm.tp, m->cm.fn);
    printf("  Actual Benign   FP = %-15lu  TN = %-15lu\n", m->cm.fp, m->cm.tn);
    printf("\n");

    unsigned long total = m->cm.tp + m->cm.fp + m->cm.tn + m->cm.fn;
    printf("Total Evaluated  : %lu\n", total);
    printf("True Positives   : %lu\n", m->cm.tp);
    printf("False Positives  : %lu\n", m->cm.fp);
    printf("True Negatives   : %lu\n", m->cm.tn);
    printf("False Negatives  : %lu\n", m->cm.fn);
    printf("Precision        : %.4f\n", m->precision);
    printf("Recall           : %.4f\n", m->recall);
    printf("F1-Score         : %.4f\n", m->f1_score);
    printf("False Positive Rate (FPR): %.4f\n", m->fpr);
    printf("False Negative Rate (FNR): %.4f\n", m->fnr);
}

/* -----------------------------------------------------------------------
 * Per-3-gram evaluation
 * ----------------------------------------------------------------------- */
static void evaluate_per_ngram(const CSVEvent *events, size_t count,
                                const Manifest *manifest,
                                EvalMetrics *out)
{
    ConfusionMatrix cm = {0, 0, 0, 0};

    for (size_t i = 0; i < count; i++)
    {
        if (events[i].matched_workload < 0)
            continue;

        const ManifestWorkload *wl = &manifest->workloads[events[i].matched_workload];
        int gt_suspicious = (strcmp(wl->ground_truth_label, "suspicious") == 0);
        int pred_suspicious = events[i].rescore_suspicious;

        if (gt_suspicious && pred_suspicious)       cm.tp++;
        else if (!gt_suspicious && pred_suspicious)  cm.fp++;
        else if (!gt_suspicious && !pred_suspicious) cm.tn++;
        else /* gt_suspicious && !pred_suspicious */ cm.fn++;
    }

    compute_metrics(&cm, out);
    print_metrics("Per-3-Gram Evaluation", out);
}

/* -----------------------------------------------------------------------
 * Per-process evaluation
 * Aggregate: a process is "predicted anomalous" if ANY event scored suspicious
 * ----------------------------------------------------------------------- */
typedef struct {
    uint32_t pid;
    int gt_suspicious;
    int pred_suspicious;
} ProcessRecord;

static void evaluate_per_process(const CSVEvent *events, size_t count,
                                  const Manifest *manifest,
                                  EvalMetrics *out)
{
    ProcessRecord procs[MAX_WORKLOADS * 4];
    int nprocs = 0;

    for (size_t i = 0; i < count; i++)
    {
        if (events[i].matched_workload < 0) continue;

        /* Find existing process record */
        int found = -1;
        for (int p = 0; p < nprocs; p++)
        {
            if (procs[p].pid == events[i].pid)
            {
                found = p;
                break;
            }
        }

        const ManifestWorkload *wl = &manifest->workloads[events[i].matched_workload];

        if (found < 0)
        {
            if (nprocs >= MAX_WORKLOADS * 4) continue;
            found = nprocs++;
            procs[found].pid = events[i].pid;
            procs[found].gt_suspicious = (strcmp(wl->ground_truth_label, "suspicious") == 0);
            procs[found].pred_suspicious = 0;
        }

        if (events[i].rescore_suspicious)
            procs[found].pred_suspicious = 1;
    }

    ConfusionMatrix cm = {0, 0, 0, 0};
    for (int p = 0; p < nprocs; p++)
    {
        if (procs[p].gt_suspicious && procs[p].pred_suspicious)       cm.tp++;
        else if (!procs[p].gt_suspicious && procs[p].pred_suspicious)  cm.fp++;
        else if (!procs[p].gt_suspicious && !procs[p].pred_suspicious) cm.tn++;
        else                                                           cm.fn++;
    }

    compute_metrics(&cm, out);
    print_metrics("Per-Process Evaluation", out);
    printf("Unique Processes Evaluated: %d\n", nprocs);
}

/* -----------------------------------------------------------------------
 * Per-workload evaluation
 * Aggregate: a workload is "predicted anomalous" if ANY event scored suspicious
 * ----------------------------------------------------------------------- */
static void evaluate_per_workload(const CSVEvent *events, size_t count,
                                   const Manifest *manifest,
                                   EvalMetrics *out)
{
    int workload_has_alert[MAX_WORKLOADS] = {0};
    int workload_has_events[MAX_WORKLOADS] = {0};

    for (size_t i = 0; i < count; i++)
    {
        if (events[i].matched_workload < 0) continue;
        workload_has_events[events[i].matched_workload] = 1;
        if (events[i].rescore_suspicious)
            workload_has_alert[events[i].matched_workload] = 1;
    }

    ConfusionMatrix cm = {0, 0, 0, 0};

    for (int w = 0; w < manifest->workload_count; w++)
    {
        if (!workload_has_events[w])
        {
            printf("  Warning: Workload '%s' has no matched events\n",
                   manifest->workloads[w].workload_id);
            continue;
        }

        const ManifestWorkload *wl = &manifest->workloads[w];
        int gt_suspicious = (strcmp(wl->ground_truth_label, "suspicious") == 0);
        int pred_anomalous = workload_has_alert[w];

        if (gt_suspicious && pred_anomalous)       cm.tp++;
        else if (!gt_suspicious && pred_anomalous)  cm.fp++;
        else if (!gt_suspicious && !pred_anomalous) cm.tn++;
        else                                        cm.fn++;
    }

    compute_metrics(&cm, out);
    print_metrics("Per-Workload Evaluation", out);

    printf("\nWorkload Detail:\n");
    printf("%-20s %-18s %-10s %-10s %-8s\n",
           "Workload", "Type", "GT Label", "Predicted", "Match?");
    printf("%-20s-%-18s-%-10s-%-10s-%-8s\n",
           "--------------------", "------------------", "----------",
           "----------", "--------");
    for (int w = 0; w < manifest->workload_count; w++)
    {
        if (!workload_has_events[w]) continue;
        const ManifestWorkload *wl = &manifest->workloads[w];
        int gt_susp = (strcmp(wl->ground_truth_label, "suspicious") == 0);
        int pred = workload_has_alert[w];
        const char *match = (gt_susp == pred) ? "OK" : "MISMATCH";
        printf("%-20s %-18s %-10s %-10s %-8s\n",
               wl->workload_id, wl->workload_type,
               wl->ground_truth_label,
               pred ? "anomalous" : "normal",
               match);
    }
}

/* -----------------------------------------------------------------------
 * Detection latency analysis
 * ----------------------------------------------------------------------- */
static void evaluate_latency(const CSVEvent *events, size_t count,
                              const Manifest *manifest)
{
    LatencyRecord records[MAX_WORKLOADS];
    memset(records, 0, sizeof(records));

    for (int w = 0; w < manifest->workload_count; w++)
    {
        const ManifestWorkload *wl = &manifest->workloads[w];
        strncpy(records[w].workload_id, wl->workload_id, sizeof(records[w].workload_id) - 1);
        strncpy(records[w].ground_truth_label, wl->ground_truth_label,
                sizeof(records[w].ground_truth_label) - 1);
        records[w].workload_start_ns = wl->start_timestamp_ns;
        records[w].has_events = 0;
        records[w].has_alert = 0;
        records[w].first_event_ns = UINT64_MAX;
        records[w].first_alert_ns = UINT64_MAX;
    }

    for (size_t i = 0; i < count; i++)
    {
        int w = events[i].matched_workload;
        if (w < 0) continue;

        if (!records[w].has_events || events[i].timestamp_ns < records[w].first_event_ns)
        {
            records[w].first_event_ns = events[i].timestamp_ns;
            records[w].has_events = 1;
        }

        if (events[i].rescore_suspicious)
        {
            if (!records[w].has_alert || events[i].timestamp_ns < records[w].first_alert_ns)
            {
                records[w].first_alert_ns = events[i].timestamp_ns;
                records[w].has_alert = 1;
            }
        }
    }

    printf("\nDetection Latency Analysis\n");
    printf("==========================\n");
    printf("NOTE: Latency = time from workload start to first anomaly alert.\n");
    printf("      This measures detection delay, not in-memory scoring speed.\n\n");

    printf("%-20s %-10s %-14s %-14s %-14s\n",
           "Workload", "GT Label", "ToFirstEvt(ms)", "ToFirstAlert(ms)", "Status");
    printf("%-20s-%-10s-%-14s-%-14s-%-14s\n",
           "--------------------", "----------", "--------------",
           "--------------", "--------------");

    for (int w = 0; w < manifest->workload_count; w++)
    {
        double to_first_evt_ms = 0.0;
        double to_first_alert_ms = 0.0;
        const char *status;

        if (!records[w].has_events)
        {
            status = "NO_EVENTS";
            printf("%-20s %-10s %-14s %-14s %-14s\n",
                   records[w].workload_id, records[w].ground_truth_label,
                   "N/A", "N/A", status);
            continue;
        }

        to_first_evt_ms = (double)(records[w].first_event_ns - records[w].workload_start_ns) / 1e6;

        if (records[w].has_alert)
        {
            to_first_alert_ms = (double)(records[w].first_alert_ns - records[w].workload_start_ns) / 1e6;
            status = "DETECTED";
        }
        else
        {
            status = "NOT_DETECTED";
        }

        char evt_buf[32], alert_buf[32];
        snprintf(evt_buf, sizeof(evt_buf), "%.2f", to_first_evt_ms);

        if (records[w].has_alert)
            snprintf(alert_buf, sizeof(alert_buf), "%.2f", to_first_alert_ms);
        else
            snprintf(alert_buf, sizeof(alert_buf), "N/A");

        printf("%-20s %-10s %-14s %-14s %-14s\n",
               records[w].workload_id, records[w].ground_truth_label,
               evt_buf, alert_buf, status);
    }
}

/* -----------------------------------------------------------------------
 * Print usage
 * ----------------------------------------------------------------------- */
static void print_usage(const char *prog)
{
    printf("Usage: %s --manifest <manifest.json> --dataset <eval.csv> --model <model.dat>\n\n", prog);
    printf("Options:\n");
    printf("  --manifest <path>   Ground-truth manifest JSON\n");
    printf("  --dataset  <path>   Evaluation dataset CSV (from eBPF collector)\n");
    printf("  --model    <path>   Model file (.dat) for re-scoring\n");
    printf("  -h, --help          Show this help\n\n");
    printf("Ground-truth labels come from the manifest, NOT from the CSV.\n");
    printf("All 3-gram events are re-scored using the model for consistency.\n");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *manifest_path = NULL;
    const char *dataset_path  = NULL;
    const char *model_path    = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--manifest") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --manifest needs path\n"); return 1; }
            manifest_path = argv[++i];
        }
        else if (strcmp(argv[i], "--dataset") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --dataset needs path\n"); return 1; }
            dataset_path = argv[++i];
        }
        else if (strcmp(argv[i], "--model") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --model needs path\n"); return 1; }
            model_path = argv[++i];
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!manifest_path || !dataset_path || !model_path)
    {
        fprintf(stderr, "Error: --manifest, --dataset, and --model are all required\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Ground-Truth Evaluation Tool (Stage 19)\n");
    printf("========================================\n");
    printf("Manifest : %s\n", manifest_path);
    printf("Dataset  : %s\n", dataset_path);
    printf("Model    : %s\n", model_path);
    printf("Threshold: %.2f (ANOMALY_THRESHOLD)\n", ANOMALY_THRESHOLD);
    printf("\n");

    /* Load model */
    NormalModel model;
    if (normal_model_load(&model, model_path) != 0)
    {
        fprintf(stderr, "Error: Failed to load model: %s\n", model_path);
        return 1;
    }
    printf("Model loaded: %zu unique 3-grams, %lu total\n",
           model.size, model.total_ngrams);

    /* Parse manifest */
    Manifest manifest;
    if (parse_manifest(manifest_path, &manifest) != 0)
    {
        fprintf(stderr, "Error: Failed to parse manifest: %s\n", manifest_path);
        return 1;
    }
    printf("Manifest loaded: %d workloads\n", manifest.workload_count);

    /* Print workload summary */
    int benign_count = 0, suspicious_count = 0;
    for (int i = 0; i < manifest.workload_count; i++)
    {
        if (strcmp(manifest.workloads[i].ground_truth_label, "benign") == 0)
            benign_count++;
        else
            suspicious_count++;
    }
    printf("  Benign workloads    : %d\n", benign_count);
    printf("  Suspicious workloads: %d\n", suspicious_count);

    /* Load CSV events */
    CSVEvent *events = NULL;
    size_t event_count = 0;
    if (load_csv_events(dataset_path, &events, &event_count) != 0)
    {
        fprintf(stderr, "Error: Failed to load dataset: %s\n", dataset_path);
        return 1;
    }
    printf("Dataset loaded: %zu events\n", event_count);

    /* Re-score all events */
    rescore_events(events, event_count, &model);

    /* Match events to workloads */
    match_events_to_workloads(events, event_count, &manifest);

    unsigned long matched = 0, unmatched = 0;
    for (size_t i = 0; i < event_count; i++)
    {
        if (events[i].matched_workload >= 0) matched++;
        else unmatched++;
    }
    printf("Events matched to workloads: %lu\n", matched);
    printf("Events unmatched           : %lu\n", unmatched);

    /* Evaluate at three levels */
    EvalMetrics ngram_metrics, process_metrics, workload_metrics;

    evaluate_per_ngram(events, event_count, &manifest, &ngram_metrics);
    evaluate_per_process(events, event_count, &manifest, &process_metrics);
    evaluate_per_workload(events, event_count, &manifest, &workload_metrics);

    /* Detection latency */
    evaluate_latency(events, event_count, &manifest);

    /* Summary */
    printf("\n\nEvaluation Summary\n");
    printf("==================\n");
    printf("%-25s %-10s %-10s %-10s\n", "Level", "Precision", "Recall", "F1-Score");
    printf("%-25s-%-10s-%-10s-%-10s\n",
           "-------------------------", "----------", "----------", "----------");

    char p1[16], r1[16], f1[16];
    char p2[16], r2[16], f2[16];
    char p3[16], r3[16], f3[16];
    snprintf(p1, sizeof(p1), "%.4f", ngram_metrics.precision);
    snprintf(r1, sizeof(r1), "%.4f", ngram_metrics.recall);
    snprintf(f1, sizeof(f1), "%.4f", ngram_metrics.f1_score);
    snprintf(p2, sizeof(p2), "%.4f", process_metrics.precision);
    snprintf(r2, sizeof(r2), "%.4f", process_metrics.recall);
    snprintf(f2, sizeof(f2), "%.4f", process_metrics.f1_score);
    snprintf(p3, sizeof(p3), "%.4f", workload_metrics.precision);
    snprintf(r3, sizeof(r3), "%.4f", workload_metrics.recall);
    snprintf(f3, sizeof(f3), "%.4f", workload_metrics.f1_score);

    printf("%-25s %-10s %-10s %-10s\n", "Per-3-Gram", p1, r1, f1);
    printf("%-25s %-10s %-10s %-10s\n", "Per-Process", p2, r2, f2);
    printf("%-25s %-10s %-10s %-10s\n", "Per-Workload", p3, r3, f3);

    printf("\nLimitations & Threats to Validity:\n");
    printf("- Controlled suspicious workloads are NOT real malware attacks.\n");
    printf("- Syscall patterns from simulated workloads may differ significantly\n");
    printf("  from actual threat actor behavior.\n");
    printf("- PID matching may miss child processes spawned by workloads.\n");
    printf("- Monotonic timestamp alignment assumes shared clock (same host).\n");
    printf("- Small sample sizes limit statistical significance.\n");
    printf("- The 0.80 threshold was not tuned on this evaluation set.\n");

    free(events);
    return 0;
}
