/*
 * model_compare.c — Side-by-Side Model Comparison on Independent CSV (Stage 18)
 *
 * Evaluates two models (A and B) against the exact same independent CSV,
 * ensuring both models are scored on identical valid evaluation records.
 *
 * Reports:
 *   | Metric                 | Model A         | Model B         |
 *   | Unique 3-grams         |                 |                 |
 *   | Total training 3-grams |                 |                 |
 *   | Evaluation records     |                 |                 |
 *   | Anomalous records      |                 |                 |
 *   | Alert rate             |                 |                 |
 *   | Average scoring latency|                 |                 |
 *   | Model file size        |                 |                 |
 *
 * TERMINOLOGY: "Alert rate" = fraction of scored records at/above threshold.
 * This is NOT a false-positive rate without verified benign ground truth.
 *
 * Usage:
 *   ./tools/model_compare --model-a <a.dat> --model-b <b.dat> --eval-csv <eval.csv>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "model.h"
#include "anomaly.h"
#include "ngram.h"

static double get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* Parse CSV header to find syscall_1/2/3 columns (1-based). */
static void parse_csv_header(const char *header_line,
                              int *col_s1, int *col_s2, int *col_s3)
{
    char hdr_buf[1024];
    strncpy(hdr_buf, header_line, sizeof(hdr_buf) - 1);
    hdr_buf[sizeof(hdr_buf) - 1] = '\0';

    char *nl = strchr(hdr_buf, '\n');
    if (nl) *nl = '\0';

    *col_s1 = -1; *col_s2 = -1; *col_s3 = -1;

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

        if      (strcmp(tok, "syscall_1") == 0) *col_s1 = cidx;
        else if (strcmp(tok, "syscall_2") == 0) *col_s2 = cidx;
        else if (strcmp(tok, "syscall_3") == 0) *col_s3 = cidx;
    }

    if (*col_s1 < 0) *col_s1 = 4;
    if (*col_s2 < 0) *col_s2 = 5;
    if (*col_s3 < 0) *col_s3 = 6;
}

/* Parsed 3-gram row */
typedef struct {
    int s1, s2, s3;
} ParsedRow;

static void print_usage(const char *prog)
{
    printf("Usage: %s --model-a <a.dat> --model-b <b.dat> --eval-csv <eval.csv>\n\n", prog);
    printf("Options:\n");
    printf("  --model-a  <path>   First model .dat file\n");
    printf("  --model-b  <path>   Second model .dat file\n");
    printf("  --eval-csv <path>   Independent evaluation CSV\n");
    printf("  -h, --help          Show this help\n\n");
    printf("Both models are scored on the exact same valid evaluation records.\n");
    printf("Alert rate is NOT a false-positive rate without verified benign ground truth.\n");
}

int main(int argc, char **argv)
{
    const char *model_a_path = NULL;
    const char *model_b_path = NULL;
    const char *eval_csv_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--model-a") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --model-a needs a path\n"); return 1; }
            model_a_path = argv[++i];
        }
        else if (strcmp(argv[i], "--model-b") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --model-b needs a path\n"); return 1; }
            model_b_path = argv[++i];
        }
        else if (strcmp(argv[i], "--eval-csv") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --eval-csv needs a path\n"); return 1; }
            eval_csv_path = argv[++i];
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!model_a_path || !model_b_path || !eval_csv_path)
    {
        fprintf(stderr, "Error: --model-a, --model-b, and --eval-csv are all required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Load both models */
    printf("Model Comparison Tool (Stage 18)\n");
    printf("================================\n");
    printf("Model A          : %s\n", model_a_path);
    printf("Model B          : %s\n", model_b_path);
    printf("Evaluation CSV   : %s\n", eval_csv_path);
    printf("\n");
    printf("DISCLAIMER: Alert rate is not a false-positive rate.\n");
    printf("  Rows have NOT been independently verified as benign.\n\n");

    NormalModel model_a, model_b;
    if (normal_model_load(&model_a, model_a_path) != 0)
    {
        fprintf(stderr, "Error: Failed to load Model A: %s\n", model_a_path);
        return 1;
    }
    if (normal_model_load(&model_b, model_b_path) != 0)
    {
        fprintf(stderr, "Error: Failed to load Model B: %s\n", model_b_path);
        return 1;
    }

    /* File sizes */
    struct stat st_a, st_b;
    long size_a = -1, size_b = -1;
    if (stat(model_a_path, &st_a) == 0) size_a = (long)st_a.st_size;
    if (stat(model_b_path, &st_b) == 0) size_b = (long)st_b.st_size;

    /* --- Phase 1: Pre-scan the CSV to extract all valid 3-gram rows --- */
    FILE *f = fopen(eval_csv_path, "r");
    if (!f)
    {
        perror("Error: Failed to open evaluation CSV");
        return 1;
    }

    char line[1024];
    if (!fgets(line, sizeof(line), f))
    {
        fprintf(stderr, "Error: Evaluation CSV is empty: %s\n", eval_csv_path);
        fclose(f);
        return 1;
    }

    int col_s1, col_s2, col_s3;
    parse_csv_header(line, &col_s1, &col_s2, &col_s3);

    /* Dynamic array of parsed rows */
    size_t rows_cap = 4096;
    size_t rows_count = 0;
    ParsedRow *rows = malloc(rows_cap * sizeof(ParsedRow));
    if (!rows) { fprintf(stderr, "Error: Memory allocation failed\n"); fclose(f); return 1; }

    unsigned long malformed_rows = 0;
    unsigned long skipped_headers = 0;

    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
        {
            skipped_headers++;
            continue;
        }

        char line_buf[1024];
        strncpy(line_buf, line, sizeof(line_buf) - 1);
        line_buf[sizeof(line_buf) - 1] = '\0';

        char *token;
        char *rest = line_buf;
        int col = 0;
        int s1 = -1, s2 = -1, s3 = -1;

        while ((token = strtok_r(rest, ",", &rest)) != NULL)
        {
            col++;
            if      (col == col_s1) s1 = atoi(token);
            else if (col == col_s2) s2 = atoi(token);
            else if (col == col_s3) s3 = atoi(token);
        }

        if (s1 >= 0 && s2 >= 0 && s3 >= 0)
        {
            if (rows_count >= rows_cap)
            {
                rows_cap *= 2;
                ParsedRow *tmp = realloc(rows, rows_cap * sizeof(ParsedRow));
                if (!tmp) { fprintf(stderr, "Error: realloc failed\n"); free(rows); fclose(f); return 1; }
                rows = tmp;
            }
            rows[rows_count].s1 = s1;
            rows[rows_count].s2 = s2;
            rows[rows_count].s3 = s3;
            rows_count++;
        }
        else
        {
            malformed_rows++;
        }
    }
    fclose(f);

    if (rows_count == 0)
    {
        printf("Warning: No valid 3-gram rows found in %s\n", eval_csv_path);
        printf("  Malformed rows: %lu\n", malformed_rows);
        printf("  Embedded header rows: %lu\n", skipped_headers);
        free(rows);
        return 0;
    }

    /* --- Phase 2: Score all valid rows with Model A --- */
    unsigned long alerts_a = 0, normal_a = 0;
    double start_a = get_time_ns();
    for (size_t i = 0; i < rows_count; i++)
    {
        NGram ngram = {{rows[i].s1, rows[i].s2, rows[i].s3}};
        double score = anomaly_score(&model_a, &ngram);
        if (score >= ANOMALY_THRESHOLD)
            alerts_a++;
        else
            normal_a++;
    }
    double end_a = get_time_ns();

    /* --- Phase 3: Score all valid rows with Model B --- */
    unsigned long alerts_b = 0, normal_b = 0;
    double start_b = get_time_ns();
    for (size_t i = 0; i < rows_count; i++)
    {
        NGram ngram = {{rows[i].s1, rows[i].s2, rows[i].s3}};
        double score = anomaly_score(&model_b, &ngram);
        if (score >= ANOMALY_THRESHOLD)
            alerts_b++;
        else
            normal_b++;
    }
    double end_b = get_time_ns();

    free(rows);

    double avg_lat_a = (end_a - start_a) / (double)rows_count;
    double avg_lat_b = (end_b - start_b) / (double)rows_count;
    double rate_a = ((double)alerts_a / (double)rows_count) * 100.0;
    double rate_b = ((double)alerts_b / (double)rows_count) * 100.0;

    /* --- Phase 4: Print comparison table --- */
    printf("Evaluation Summary\n");
    printf("==================\n");
    printf("Malformed Rows Skipped : %lu\n", malformed_rows);
    printf("Embedded Header Rows   : %lu\n", skipped_headers);
    printf("\n");
    printf("Comparison Table\n");
    printf("================\n\n");

    printf("%-30s | %-20s | %-20s\n", "Metric", "Model A", "Model B");
    printf("%-30s-+-%-20s-+-%-20s\n", "------------------------------",
           "--------------------", "--------------------");

    printf("%-30s | %-20zu | %-20zu\n", "Unique 3-grams",
           model_a.size, model_b.size);
    printf("%-30s | %-20lu | %-20lu\n", "Total training 3-grams",
           model_a.total_ngrams, model_b.total_ngrams);
    printf("%-30s | %-20lu | %-20lu\n", "Evaluation records",
           (unsigned long)rows_count, (unsigned long)rows_count);
    printf("%-30s | %-20lu | %-20lu\n", "Anomalous records (alerts)",
           alerts_a, alerts_b);
    printf("%-30s | %-20lu | %-20lu\n", "Normal records",
           normal_a, normal_b);

    char rate_buf_a[32], rate_buf_b[32];
    snprintf(rate_buf_a, sizeof(rate_buf_a), "%.4f%%", rate_a);
    snprintf(rate_buf_b, sizeof(rate_buf_b), "%.4f%%", rate_b);
    printf("%-30s | %-20s | %-20s\n", "Alert rate (NOT FPR)", rate_buf_a, rate_buf_b);

    char lat_buf_a[32], lat_buf_b[32];
    snprintf(lat_buf_a, sizeof(lat_buf_a), "%.2f ns", avg_lat_a);
    snprintf(lat_buf_b, sizeof(lat_buf_b), "%.2f ns", avg_lat_b);
    printf("%-30s | %-20s | %-20s\n", "Avg scoring latency", lat_buf_a, lat_buf_b);

    char size_buf_a[32], size_buf_b[32];
    snprintf(size_buf_a, sizeof(size_buf_a), "%ld bytes", size_a);
    snprintf(size_buf_b, sizeof(size_buf_b), "%ld bytes", size_b);
    printf("%-30s | %-20s | %-20s\n", "Model file size", size_buf_a, size_buf_b);

    printf("\nNote: Both models were evaluated on exactly %lu identical valid records.\n",
           (unsigned long)rows_count);
    printf("Note: Alert rate is NOT a false-positive rate without verified benign labels.\n");

    return 0;
}
