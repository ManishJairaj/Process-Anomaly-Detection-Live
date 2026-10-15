/*
 * eval_baseline_model.c — Controlled Model Evaluation Tool
 *
 * Modes:
 *
 * A) Legacy positional mode (backward compatible):
 *      ./eval_baseline_model [model.dat] [baseline.csv]
 *    Runs temporal 70/30 block split + optional ADFA-LD attack evaluation.
 *
 * B) Independent CSV evaluation mode (Stage 18):
 *      ./eval_baseline_model --model <model.dat> --eval-csv <eval.csv>
 *    Scores every row in the independent CSV without any train/test split.
 *    Reports anomaly alert rate (NOT false-positive rate — labels are not
 *    verified benign ground truth).
 *
 * NOTE ON TERMINOLOGY:
 *   "Alert rate" = fraction of scored records that exceed ANOMALY_THRESHOLD.
 *   This is NOT a false-positive rate. A genuine FPR requires independently
 *   verified benign ground truth, which the live eBPF dataset does not have.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
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

/* -----------------------------------------------------------------------
 * parse_csv_header: detect 1-based column indices by header name.
 * Falls back to hard-coded columns 4/5/6 if standard header absent.
 * ----------------------------------------------------------------------- */
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

    /* Fallback if not found by name */
    if (*col_s1 < 0) *col_s1 = 4;
    if (*col_s2 < 0) *col_s2 = 5;
    if (*col_s3 < 0) *col_s3 = 6;
}

/* -----------------------------------------------------------------------
 * Section A: Legacy temporal 70/30 block split evaluation
 *
 * LIMITATION NOTE: This function labels rows arriving after the 70%
 * temporal boundary as "held-out". However, those rows are NOT verified
 * benign — they are the same kind of detector-labelled records used during
 * training. The "FP" and "FPR" labels below are RETAINED for backward
 * compatibility with existing tests (test_trainer_detector_compat
 * INTEGRATION 7 checks for "Held-out Evaluated (30%)"). They do NOT imply
 * genuine false-positive measurement.
 * ----------------------------------------------------------------------- */
static void evaluate_heldout_benign(const NormalModel *model, const char *csv_path)
{
    printf("\n1. Held-Out Validation Evaluation (Temporal 70/30 Block Split)\n");
    printf("================================================================\n");
    printf("NOTE: Rows are NOT independently verified benign. Alert rate only.\n");

    FILE *f = fopen(csv_path, "r");
    if (!f)
    {
        perror("Failed to open input dataset CSV");
        return;
    }

    char line[1024];
    unsigned long total_data_rows = 0;

    /* Pass 1: Count total valid data rows (excluding header lines) */
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
            continue; /* Skip main header and duplicate headers */
        total_data_rows++;
    }

    if (total_data_rows == 0)
    {
        printf("Note: No valid data rows found in %s\n", csv_path);
        fclose(f);
        return;
    }

    /* Dynamic 70% training split limit */
    unsigned long train_split_rows = (unsigned long)(total_data_rows * 0.70);

    rewind(f);

    /* Detect column positions from header */
    int col_s1, col_s2, col_s3;
    if (fgets(line, sizeof(line), f))
        parse_csv_header(line, &col_s1, &col_s2, &col_s3);
    else
    {
        fclose(f);
        return;
    }

    unsigned long row_idx = 0;
    unsigned long train_rows_skipped = 0;
    unsigned long heldout_rows_evaluated = 0;
    unsigned long malformed_rows = 0;

    unsigned long tn_count = 0; /* Score < ANOMALY_THRESHOLD */
    unsigned long fp_count = 0; /* Score >= ANOMALY_THRESHOLD */

    double start_time = get_time_ns();

    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
            continue;

        row_idx++;
        if (row_idx <= train_split_rows)
        {
            train_rows_skipped++;
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
            NGram ngram = {{s1, s2, s3}};
            double score = anomaly_score(model, &ngram);

            if (score >= ANOMALY_THRESHOLD)
                fp_count++;
            else
                tn_count++;

            heldout_rows_evaluated++;
        }
        else
        {
            malformed_rows++;
        }
    }

    double end_time = get_time_ns();
    fclose(f);

    double total_time_ms = (end_time - start_time) / 1e6;
    double avg_latency_ns = (heldout_rows_evaluated > 0)
                            ? (end_time - start_time) / heldout_rows_evaluated : 0.0;
    double alert_rate = (heldout_rows_evaluated > 0)
                        ? ((double)fp_count / heldout_rows_evaluated) * 100.0 : 0.0;

    printf("Total CSV Data Rows          : %lu\n", total_data_rows);
    printf("Training Block Skipped (70%%): %lu\n", train_rows_skipped);
    printf("Held-out Evaluated (30%%)    : %lu\n", heldout_rows_evaluated);
    printf("Malformed Rows (skipped)    : %lu\n", malformed_rows);
    printf("Below Threshold             : %lu\n", tn_count);
    printf("At/Above Threshold (alerts) : %lu\n", fp_count);
    /* Retain legacy "False Positives" label for backward-compat test matching */
    printf("False Positives (FP)        : %lu\n", fp_count);
    printf("False Positive Rate (FPR)   : %.4f%%\n", alert_rate);
    printf("Anomaly Alert Rate          : %.4f%% (NOT a verified FPR)\n", alert_rate);
    printf("Total Scoring Time          : %.2f ms\n", total_time_ms);
    printf("Avg Per-Event Latency       : %.2f ns (%.4f us)\n",
           avg_latency_ns, avg_latency_ns / 1000.0);
}

/* -----------------------------------------------------------------------
 * Section B: Independent CSV evaluation (Stage 18)
 *
 * Scores every valid row in the evaluation CSV. No rows are skipped as a
 * "training set". This is only meaningful when eval_csv is genuinely
 * independent of the model's training data.
 *
 * Terminology: "alert_count" — records where score >= ANOMALY_THRESHOLD.
 * NOT called "false positives" because labels are not verified benign.
 * ----------------------------------------------------------------------- */
static void evaluate_independent_csv(const NormalModel *model,
                                     const char *model_path,
                                     const char *eval_csv_path)
{
    printf("\nIndependent CSV Evaluation\n");
    printf("==========================\n");
    printf("Model            : %s\n", model_path);
    printf("Evaluation CSV   : %s\n", eval_csv_path);
    printf("\n");
    printf("DISCLAIMER: Alert rate is not a false-positive rate.\n");
    printf("  Rows in this dataset have NOT been independently verified as benign.\n");
    printf("  A genuine FPR requires a dataset of known-clean activity.\n");
    printf("\n");

    FILE *f = fopen(eval_csv_path, "r");
    if (!f)
    {
        perror("Error: Failed to open evaluation CSV");
        return;
    }

    char line[1024];

    /* Read and parse header */
    if (!fgets(line, sizeof(line), f))
    {
        fprintf(stderr, "Error: Evaluation CSV is empty: %s\n", eval_csv_path);
        fclose(f);
        return;
    }

    int col_s1, col_s2, col_s3;
    parse_csv_header(line, &col_s1, &col_s2, &col_s3);

    unsigned long total_rows = 0;
    unsigned long valid_rows = 0;
    unsigned long alert_count = 0;    /* score >= threshold */
    unsigned long normal_count = 0;   /* score < threshold */
    unsigned long malformed_rows = 0;
    unsigned long skipped_headers = 0;

    double start_time = get_time_ns();

    while (fgets(line, sizeof(line), f))
    {
        /* Skip embedded duplicate headers */
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
        {
            skipped_headers++;
            continue;
        }

        total_rows++;

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
            NGram ngram = {{s1, s2, s3}};
            double score = anomaly_score(model, &ngram);

            if (score >= ANOMALY_THRESHOLD)
                alert_count++;
            else
                normal_count++;

            valid_rows++;
        }
        else
        {
            malformed_rows++;
        }
    }

    double end_time = get_time_ns();
    fclose(f);

    double total_time_ms = (end_time - start_time) / 1e6;
    double avg_latency_ns = (valid_rows > 0)
                            ? (end_time - start_time) / valid_rows : 0.0;
    double alert_rate = (valid_rows > 0)
                        ? ((double)alert_count / valid_rows) * 100.0 : 0.0;

    if (valid_rows == 0)
    {
        printf("Warning: No valid 3-gram rows found in %s\n", eval_csv_path);
        printf("  Total raw rows : %lu\n", total_rows);
        printf("  Malformed      : %lu\n", malformed_rows);
        printf("  Header rows    : %lu\n", skipped_headers);
        return;
    }

    printf("Total Raw Rows           : %lu\n", total_rows);
    printf("Embedded Header Rows     : %lu\n", skipped_headers);
    printf("Malformed Rows (skipped) : %lu\n", malformed_rows);
    printf("Valid Rows Scored        : %lu\n", valid_rows);
    printf("Below Threshold (normal) : %lu\n", normal_count);
    printf("At/Above Threshold (alerts): %lu\n", alert_count);
    printf("Anomaly Alert Rate       : %.4f%% (NOT a verified FPR)\n", alert_rate);
    printf("Total Scoring Time       : %.2f ms\n", total_time_ms);
    printf("Avg Per-Event Latency    : %.2f ns (%.4f us)\n",
           avg_latency_ns, avg_latency_ns / 1000.0);
}

/* -----------------------------------------------------------------------
 * Leakage warning: compare eval CSV against a known training CSV by inode.
 * Uses stat() to compare device+inode — avoids re-reading 353 MB files.
 * A different inode does NOT prove independence; it only rules out the
 * trivial case of an identical file.
 * ----------------------------------------------------------------------- */
static void check_leakage_warning(const char *model_path,
                                  const char *eval_csv_path)
{
    /* Attempt to find a training CSV path from a provenance file */
    char prov_path[512];
    snprintf(prov_path, sizeof(prov_path), "%s.provenance.json", model_path);

    char train_csv[512] = "";
    FILE *pf = fopen(prov_path, "r");
    if (pf)
    {
        char pline[512];
        while (fgets(pline, sizeof(pline), pf))
        {
            /* Look for "training_dataset_path": "..." */
            const char *key = "\"training_dataset_path\"";
            char *found = strstr(pline, key);
            if (found)
            {
                char *q1 = strchr(found + strlen(key), '"');
                if (q1)
                {
                    char *q2 = strchr(q1 + 1, '"');
                    if (q2)
                    {
                        size_t len = (size_t)(q2 - q1 - 1);
                        if (len < sizeof(train_csv) - 1)
                        {
                            strncpy(train_csv, q1 + 1, len);
                            train_csv[len] = '\0';
                        }
                    }
                }
            }
        }
        fclose(pf);
    }

    printf("\nLeakage / Independence Check\n");
    printf("============================\n");

    if (train_csv[0] == '\0')
    {
        printf("Provenance file not found: %s\n", prov_path);
        printf("Cannot check training dataset path. Run gen_model_provenance first.\n");
    }
    else
    {
        printf("Provenance training CSV  : %s\n", train_csv);
        printf("Evaluation CSV           : %s\n", eval_csv_path);

        /* Compare file identity by device + inode */
        struct stat st_train, st_eval;
        int train_stat = stat(train_csv, &st_train);
        int eval_stat  = stat(eval_csv_path, &st_eval);

        if (train_stat == 0 && eval_stat == 0 &&
            st_train.st_dev == st_eval.st_dev &&
            st_train.st_ino == st_eval.st_ino)
        {
            printf("\n");
            printf("*** WARNING: TRAINING DATA LEAKAGE DETECTED ***\n");
            printf("  The evaluation CSV is the SAME FILE as the training dataset.\n");
            printf("  (Same device %lu, inode %lu)\n",
                   (unsigned long)st_train.st_dev,
                   (unsigned long)st_train.st_ino);
            printf("  Results from this evaluation are NOT independent.\n");
            printf("  Collect a new dataset with the eBPF detector before reporting.\n");
        }
        else if (train_stat == 0 && eval_stat == 0)
        {
            printf("Files have different inodes — not the identical file.\n");
            printf("WARNING: Different filename/inode does NOT prove independence.\n");
            printf("  Dataset contents may still overlap. Use a separately collected\n");
            printf("  dataset gathered after training was complete.\n");
        }
        else
        {
            if (train_stat != 0)
                printf("Note: Training CSV not accessible (may have moved): %s\n", train_csv);
            if (eval_stat  != 0)
                printf("Note: Evaluation CSV not accessible: %s\n", eval_csv_path);
        }
    }
    printf("\n");
}

/* -----------------------------------------------------------------------
 * ADFA-LD attack evaluation (unchanged from original)
 * ----------------------------------------------------------------------- */
static void score_attack_file(const char *filepath, const NormalModel *model,
                               unsigned long *total_files, unsigned long *detected_files,
                               unsigned long *total_ngrams, unsigned long *unseen_ngrams)
{
    FILE *f = fopen(filepath, "r");
    if (!f) return;

    int syscalls[20000];
    int count = 0;
    int val;
    while (fscanf(f, "%d", &val) == 1 && count < 20000)
        syscalls[count++] = val;
    fclose(f);

    if (count < 3) return;

    (*total_files)++;
    int file_detected = 0;

    for (int i = 0; i <= count - 3; i++)
    {
        NGram ngram = {{syscalls[i], syscalls[i+1], syscalls[i+2]}};
        (*total_ngrams)++;
        double score = anomaly_score(model, &ngram);
        if (score >= ANOMALY_THRESHOLD)
        {
            (*unseen_ngrams)++;
            file_detected = 1;
        }
    }

    if (file_detected)
        (*detected_files)++;
}

static void walk_attack_dir(const char *dir_path, const NormalModel *model,
                            unsigned long *total_files, unsigned long *detected_files,
                            unsigned long *total_ngrams, unsigned long *unseen_ngrams)
{
    DIR *dir = opendir(dir_path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(path, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode))
            walk_attack_dir(path, model, total_files, detected_files, total_ngrams, unseen_ngrams);
        else if (S_ISREG(st.st_mode))
            score_attack_file(path, model, total_files, detected_files, total_ngrams, unseen_ngrams);
    }
    closedir(dir);
}

static void evaluate_adfa_attack_traces(const NormalModel *model, const char *attack_dir)
{
    printf("\n2. ADFA-LD Attack Workload Evaluation\n");
    printf("======================================\n");
    printf("NOTE: ADFA-LD uses 32-bit x86 syscall IDs; live collector uses x86_64.\n");
    printf("      These results are indicative only — not validated detection recall.\n");

    unsigned long attack_files = 0;
    unsigned long detected_attacks = 0;
    unsigned long total_attack_ngrams = 0;
    unsigned long unseen_attack_ngrams = 0;

    walk_attack_dir(attack_dir, model, &attack_files, &detected_attacks,
                    &total_attack_ngrams, &unseen_attack_ngrams);

    if (attack_files == 0)
    {
        printf("Note: Attack directory %s not found or empty.\n", attack_dir);
        return;
    }

    double file_recall = ((double)detected_attacks / attack_files) * 100.0;
    double ngram_ratio = (total_attack_ngrams > 0)
                         ? ((double)unseen_attack_ngrams / total_attack_ngrams) * 100.0 : 0.0;

    printf("Attack Trace Files Evaluated: %lu\n", attack_files);
    printf("Detected Attack Traces (TP) : %lu\n", detected_attacks);
    printf("Missed Attack Traces (FN)   : %lu\n", attack_files - detected_attacks);
    printf("Attack Trace Recall         : %.2f%%\n", file_recall);
    printf("Total Attack 3-grams        : %lu\n", total_attack_ngrams);
    printf("Unseen Attack 3-grams       : %lu (%.2f%%)\n", unseen_attack_ngrams, ngram_ratio);
}

/* -----------------------------------------------------------------------
 * print_usage
 * ----------------------------------------------------------------------- */
static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s [model.dat] [baseline.csv]              (legacy positional mode)\n", prog);
    printf("  %s --model <m.dat> --eval-csv <eval.csv>   (independent evaluation)\n\n", prog);
    printf("Options:\n");
    printf("  --model   <path>   Path to model .dat file\n");
    printf("  --eval-csv <path>  Path to independent evaluation CSV\n");
    printf("  -h, --help         Show this help\n\n");
    printf("The --eval-csv mode scores every row in the evaluation CSV and reports\n");
    printf("an anomaly alert rate. This is NOT a false-positive rate unless the\n");
    printf("dataset has independently verified benign ground truth.\n");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *model_path    = NULL;
    const char *eval_csv_path = NULL;
    const char *legacy_csv    = NULL;   /* positional argv[2] path */
    int named_mode = 0;                 /* 1 = --model/--eval-csv mode */

    /* Parse arguments */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--model") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --model requires a path argument\n");
                return 1;
            }
            model_path = argv[++i];
            named_mode = 1;
        }
        else if (strcmp(argv[i], "--eval-csv") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "Error: --eval-csv requires a path argument\n");
                return 1;
            }
            eval_csv_path = argv[++i];
            named_mode = 1;
        }
        else if (model_path == NULL && !named_mode)
        {
            /* Positional: first non-flag arg = model */
            model_path = argv[i];
        }
        else if (legacy_csv == NULL && !named_mode)
        {
            /* Positional: second non-flag arg = csv */
            legacy_csv = argv[i];
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Apply defaults for legacy positional mode */
    if (!named_mode)
    {
        if (model_path == NULL) model_path = "baseline_model.dat";
        if (legacy_csv == NULL) legacy_csv = "baseline_syscalls.csv";
    }

    /* Validate required args for named mode */
    if (named_mode && model_path == NULL)
    {
        fprintf(stderr, "Error: --model is required in named mode\n");
        return 1;
    }
    if (named_mode && eval_csv_path == NULL)
    {
        fprintf(stderr, "Error: --eval-csv is required\n");
        return 1;
    }

    /* Load model */
    printf("Controlled Model Evaluation Tool\n");
    printf("=================================\n");
    printf("Target Model File  : %s\n", model_path);
    if (named_mode)
        printf("Evaluation CSV     : %s\n", eval_csv_path);
    else
        printf("Baseline Dataset   : %s\n", legacy_csv);

    NormalModel model;
    if (normal_model_load(&model, model_path) != 0)
    {
        fprintf(stderr, "Error: Failed to load model file %s\n", model_path);
        return 1;
    }

    printf("\nLoaded Model Summary:\n");
    printf("---------------------\n");
    printf("Magic              : 0x%08X (Expected 0x5041444D)\n", MODEL_MAGIC);
    printf("Version            : %u\n", MODEL_VERSION);
    printf("Unique 3-Grams     : %zu\n", model.size);
    printf("Total 3-Grams      : %lu\n", model.total_ngrams);

    if (named_mode)
    {
        /* --- Stage 18: Independent CSV evaluation mode --- */
        check_leakage_warning(model_path, eval_csv_path);
        evaluate_independent_csv(&model, model_path, eval_csv_path);
    }
    else
    {
        /* --- Legacy mode: temporal split + ADFA-LD --- */
        const char *attack_dir = "datasets/ADFA-LD/ADFA-LD/Attack_Data_Master";
        evaluate_heldout_benign(&model, legacy_csv);
        evaluate_adfa_attack_traces(&model, attack_dir);
    }

    return 0;
}
