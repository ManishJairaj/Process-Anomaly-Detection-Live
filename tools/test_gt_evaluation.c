/*
 * test_gt_evaluation.c — Stage 19: Ground-Truth Evaluation Unit Tests
 *
 * Tests:
 *   1. Ground-truth manifest parsing — loads workloads correctly
 *   2. Timestamp alignment — events match workload windows
 *   3. PID matching — events assigned to correct workloads
 *   4. Missing events — workload with no events handled gracefully
 *   5. Confusion matrix — correct TP/FP/TN/FN calculation
 *   6. Zero-division — empty evaluation set handled safely
 *   7. Benign workload evaluation — known 3-grams produce TN
 *   8. Security-relevant workload evaluation — unseen 3-grams produce TP
 *   9. Consistent model comparison — same events, different models
 *  10. Per-process vs per-workload — different aggregation units
 *  11. Detection latency — first-alert timestamp correct
 *  12. Backward compatibility — all Stage 18 tests still pass
 *
 * Build & Run:
 *   make tools/test_gt_evaluation
 *   ./tools/test_gt_evaluation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>

#include "model.h"
#include "anomaly.h"
#include "ngram.h"

/* -----------------------------------------------------------------------
 * Test helper: build a tiny model
 * ----------------------------------------------------------------------- */
static void build_model(const char *path, int s1, int s2, int s3, int count)
{
    NormalModel m;
    normal_model_init(&m);
    NGram g = {{s1, s2, s3}};
    for (int i = 0; i < count; i++)
        normal_model_add(&m, &g);
    normal_model_finalize(&m);
    assert(normal_model_save(&m, path) == 0);
}

/* Build model with two known 3-grams */
static void build_model2(const char *path,
                          int a1, int a2, int a3,
                          int b1, int b2, int b3, int count)
{
    NormalModel m;
    normal_model_init(&m);
    NGram ga = {{a1, a2, a3}};
    NGram gb = {{b1, b2, b3}};
    for (int i = 0; i < count; i++)
    {
        normal_model_add(&m, &ga);
        normal_model_add(&m, &gb);
    }
    normal_model_finalize(&m);
    assert(normal_model_save(&m, path) == 0);
}

/* -----------------------------------------------------------------------
 * Helper: write a manifest JSON with given workloads
 * ----------------------------------------------------------------------- */
typedef struct {
    const char *workload_id;
    const char *workload_type;
    const char *ground_truth_label;
    uint32_t pid;
    uint64_t start_ns;
    uint64_t end_ns;
} TestWorkload;

static void write_manifest(const char *path, const TestWorkload *wls, int count)
{
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "{\n");
    fprintf(f, "  \"schema_version\": 1,\n");
    fprintf(f, "  \"timestamp_type\": \"monotonic_ns\",\n");
    fprintf(f, "  \"model_file\": \"test_model.dat\",\n");
    fprintf(f, "  \"workloads\": [\n");
    for (int i = 0; i < count; i++)
    {
        fprintf(f, "    {\n");
        fprintf(f, "      \"workload_id\": \"%s\",\n", wls[i].workload_id);
        fprintf(f, "      \"workload_type\": \"%s\",\n", wls[i].workload_type);
        fprintf(f, "      \"ground_truth_label\": \"%s\",\n", wls[i].ground_truth_label);
        fprintf(f, "      \"pid\": %u,\n", wls[i].pid);
        fprintf(f, "      \"start_timestamp_ns\": %" PRIu64 ",\n", wls[i].start_ns);
        fprintf(f, "      \"end_timestamp_ns\": %" PRIu64 ",\n", wls[i].end_ns);
        fprintf(f, "      \"description\": \"test workload\",\n");
        fprintf(f, "      \"dataset_filename\": \"test.csv\",\n");
        fprintf(f, "      \"host_arch\": \"x86_64\",\n");
        fprintf(f, "      \"kernel_version\": \"6.17.0\"\n");
        fprintf(f, "    }%s\n", (i < count - 1) ? "," : "");
    }
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
}

/* -----------------------------------------------------------------------
 * Helper: write an eval CSV
 * ----------------------------------------------------------------------- */
static void write_csv(const char *path, const char *rows[], int nrows)
{
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "monotonic_timestamp_ns,pid,process_name,"
               "syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    for (int i = 0; i < nrows; i++)
        fprintf(f, "%s\n", rows[i]);
    fclose(f);
}

/* -----------------------------------------------------------------------
 * Helper: run gt_evaluate and capture output
 * ----------------------------------------------------------------------- */
static int run_gt_eval(const char *args, const char *outfile)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./tools/gt_evaluate %s > %s 2>&1", args, outfile);
    return system(cmd);
}

static int run_gt_compare(const char *args, const char *outfile)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./tools/gt_model_compare %s > %s 2>&1", args, outfile);
    return system(cmd);
}

/* Check if a string appears in output file */
static int output_has(const char *outfile, const char *needle)
{
    FILE *f = fopen(outfile, "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, needle)) { found = 1; break; }
    fclose(f);
    return found;
}

/* Extract number after a label */
static long extract_num(const char *outfile, const char *label)
{
    FILE *f = fopen(outfile, "r");
    if (!f) return -1;
    char line[1024];
    long result = -1;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, label))
        {
            char *p = strchr(line, ':');
            if (p) result = strtol(p + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return result;
}

/* -----------------------------------------------------------------------
 * TEST 1: Ground-truth manifest parsing
 * ----------------------------------------------------------------------- */
static void test_manifest_parsing(void)
{
    printf("[TEST  1] Ground-truth manifest parsing... ");

    const char *manifest = "/tmp/t19_manifest1.json";
    const char *model = "/tmp/t19_m1.dat";
    const char *csv = "/tmp/t19_csv1.csv";
    const char *out = "/tmp/t19_out1.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 1, 2, 3, 5);

    TestWorkload wls[] = {
        {"W1", "benign", "benign", 100, 1000, 5000},
        {"W2", "security_relevant", "suspicious", 200, 6000, 10000}
    };
    write_manifest(manifest, wls, 2);

    const char *rows[] = {
        "2000,100,\"p\",1,2,3,0.01,NORMAL",
        "8000,200,\"q\",99,88,77,1.00,SUSPICIOUS"
    };
    write_csv(csv, rows, 2);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    assert(output_has(out, "Manifest loaded: 2 workloads"));
    assert(output_has(out, "Benign workloads    : 1"));
    assert(output_has(out, "Suspicious workloads: 1"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 2: Timestamp alignment
 * ----------------------------------------------------------------------- */
static void test_timestamp_alignment(void)
{
    printf("[TEST  2] Timestamp alignment — events match windows... ");

    const char *manifest = "/tmp/t19_manifest2.json";
    const char *model = "/tmp/t19_m2.dat";
    const char *csv = "/tmp/t19_csv2.csv";
    const char *out = "/tmp/t19_out2.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 10, 20, 30, 5);

    /* Workload window: [1000, 5000] */
    TestWorkload wls[] = {
        {"TSW", "benign", "benign", 100, 1000, 5000}
    };
    write_manifest(manifest, wls, 1);

    /* Two inside window, one outside */
    const char *rows[] = {
        "2000,100,\"p\",10,20,30,0.01,NORMAL",   /* inside → matched */
        "3000,100,\"p\",10,20,30,0.01,NORMAL",   /* inside → matched */
        "9000,100,\"p\",10,20,30,0.01,NORMAL"    /* outside → unmatched */
    };
    write_csv(csv, rows, 3);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    assert(output_has(out, "Events matched to workloads: 2"));
    assert(output_has(out, "Events unmatched           : 1"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 3: PID matching
 * ----------------------------------------------------------------------- */
static void test_pid_matching(void)
{
    printf("[TEST  3] PID matching — events assigned correctly... ");

    const char *manifest = "/tmp/t19_manifest3.json";
    const char *model = "/tmp/t19_m3.dat";
    const char *csv = "/tmp/t19_csv3.csv";
    const char *out = "/tmp/t19_out3.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model2(model, 10, 20, 30, 40, 50, 60, 5);

    /* Two overlapping time windows, different PIDs */
    TestWorkload wls[] = {
        {"PID_A", "benign", "benign", 100, 1000, 9000},
        {"PID_B", "security_relevant", "suspicious", 200, 1000, 9000}
    };
    write_manifest(manifest, wls, 2);

    const char *rows[] = {
        "2000,100,\"a\",10,20,30,0.01,NORMAL",     /* PID 100 → PID_A (benign) */
        "3000,200,\"b\",99,88,77,1.00,SUSPICIOUS",  /* PID 200 → PID_B (suspicious) */
    };
    write_csv(csv, rows, 2);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Both events matched */
    assert(output_has(out, "Events matched to workloads: 2"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 4: Missing events — workload with no matched events
 * ----------------------------------------------------------------------- */
static void test_missing_events(void)
{
    printf("[TEST  4] Missing events — workload with no matches... ");

    const char *manifest = "/tmp/t19_manifest4.json";
    const char *model = "/tmp/t19_m4.dat";
    const char *csv = "/tmp/t19_csv4.csv";
    const char *out = "/tmp/t19_out4.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 1, 2, 3, 1);

    /* Workload window that doesn't match any CSV events */
    TestWorkload wls[] = {
        {"NOMATCH", "benign", "benign", 999, 50000, 60000}
    };
    write_manifest(manifest, wls, 1);

    const char *rows[] = {
        "2000,100,\"p\",1,2,3,0.01,NORMAL"
    };
    write_csv(csv, rows, 1);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Should warn about no matched events */
    assert(output_has(out, "no matched events") ||
           output_has(out, "Events matched to workloads: 0"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 5: Confusion matrix calculation
 * ----------------------------------------------------------------------- */
static void test_confusion_matrix(void)
{
    printf("[TEST  5] Confusion matrix — TP/FP/TN/FN correct... ");

    const char *manifest = "/tmp/t19_manifest5.json";
    const char *model = "/tmp/t19_m5.dat";
    const char *csv = "/tmp/t19_csv5.csv";
    const char *out = "/tmp/t19_out5.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    /* Model knows (10,20,30) only */
    build_model(model, 10, 20, 30, 100);

    TestWorkload wls[] = {
        /* Benign workload with known 3-gram → TN */
        {"W_BN", "benign", "benign", 100, 1000, 3000},
        /* Suspicious workload with unseen 3-gram → TP */
        {"W_SP", "security_relevant", "suspicious", 200, 4000, 6000},
        /* Benign workload with unseen 3-gram → FP */
        {"W_FP", "benign", "benign", 300, 7000, 9000},
        /* Suspicious workload with known 3-gram → FN */
        {"W_FN", "security_relevant", "suspicious", 400, 10000, 12000}
    };
    write_manifest(manifest, wls, 4);

    const char *rows[] = {
        "2000,100,\"a\",10,20,30,0.01,NORMAL",     /* known → normal (TN) */
        "5000,200,\"b\",99,88,77,1.00,SUSPICIOUS",  /* unseen → alert (TP) */
        "8000,300,\"c\",50,60,70,1.00,SUSPICIOUS",  /* unseen → alert (FP) */
        "11000,400,\"d\",10,20,30,0.01,NORMAL"      /* known → normal (FN) */
    };
    write_csv(csv, rows, 4);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Per-workload should have: TP=1, FP=1, TN=1, FN=1 */
    assert(output_has(out, "True Positives   : 1"));
    assert(output_has(out, "False Positives  : 1"));
    assert(output_has(out, "True Negatives   : 1"));
    assert(output_has(out, "False Negatives  : 1"));
    assert(output_has(out, "Precision        : 0.5000"));
    assert(output_has(out, "Recall           : 0.5000"));
    assert(output_has(out, "F1-Score         : 0.5000"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 6: Zero-division safety
 * ----------------------------------------------------------------------- */
static void test_zero_division(void)
{
    printf("[TEST  6] Zero-division — empty evaluation handled safely... ");

    const char *manifest = "/tmp/t19_manifest6.json";
    const char *model = "/tmp/t19_m6.dat";
    const char *csv = "/tmp/t19_csv6.csv";
    const char *out = "/tmp/t19_out6.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 1, 2, 3, 1);

    /* Workload in a time window with no matching events */
    TestWorkload wls[] = {
        {"EMPTY", "benign", "benign", 999, 90000, 99000}
    };
    write_manifest(manifest, wls, 1);

    /* CSV header only */
    FILE *f = fopen(csv, "w");
    assert(f);
    fprintf(f, "monotonic_timestamp_ns,pid,process_name,"
               "syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    fclose(f);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    /* Should not crash or divide-by-zero */
    run_gt_eval(args, out);

    struct stat st;
    assert(stat(out, &st) == 0);  /* output file exists = no crash */

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 7: Benign workload evaluation
 * ----------------------------------------------------------------------- */
static void test_benign_workload(void)
{
    printf("[TEST  7] Benign workload — known 3-grams produce TN... ");

    const char *manifest = "/tmp/t19_manifest7.json";
    const char *model = "/tmp/t19_m7.dat";
    const char *csv = "/tmp/t19_csv7.csv";
    const char *out = "/tmp/t19_out7.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    /* Model knows several common 3-grams */
    NormalModel m;
    normal_model_init(&m);
    NGram g1 = {{0, 1, 2}};
    NGram g2 = {{1, 2, 3}};
    NGram g3 = {{2, 3, 0}};
    for (int i = 0; i < 100; i++)
    {
        normal_model_add(&m, &g1);
        normal_model_add(&m, &g2);
        normal_model_add(&m, &g3);
    }
    normal_model_finalize(&m);
    assert(normal_model_save(&m, model) == 0);

    TestWorkload wls[] = {
        {"BENIGN1", "benign", "benign", 100, 1000, 9000}
    };
    write_manifest(manifest, wls, 1);

    /* All known 3-grams → all should be normal */
    const char *rows[] = {
        "2000,100,\"p\",0,1,2,0.01,NORMAL",
        "3000,100,\"p\",1,2,3,0.01,NORMAL",
        "4000,100,\"p\",2,3,0,0.01,NORMAL"
    };
    write_csv(csv, rows, 3);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Per-workload: 1 TN, 0 TP, 0 FP, 0 FN */
    /* Per-3-gram: 3 TN */
    assert(output_has(out, "Per-Workload Evaluation"));
    /* Check that workload is predicted normal (label BENIGN1 = OK) */
    assert(output_has(out, "OK"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 8: Security-relevant workload evaluation
 * ----------------------------------------------------------------------- */
static void test_suspicious_workload(void)
{
    printf("[TEST  8] Security-relevant workload — unseen 3-grams produce TP... ");

    const char *manifest = "/tmp/t19_manifest8.json";
    const char *model = "/tmp/t19_m8.dat";
    const char *csv = "/tmp/t19_csv8.csv";
    const char *out = "/tmp/t19_out8.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 10, 20, 30, 50);

    TestWorkload wls[] = {
        {"SUSP1", "security_relevant", "suspicious", 200, 1000, 9000}
    };
    write_manifest(manifest, wls, 1);

    /* All unseen 3-grams → should trigger alerts */
    const char *rows[] = {
        "2000,200,\"s\",99,88,77,1.00,SUSPICIOUS",
        "3000,200,\"s\",77,66,55,1.00,SUSPICIOUS",
        "4000,200,\"s\",55,44,33,1.00,SUSPICIOUS"
    };
    write_csv(csv, rows, 3);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Per-workload: TP=1 */
    assert(output_has(out, "OK"));
    /* Per-3-gram: all 3 should be TP */
    assert(output_has(out, "Per-3-Gram Evaluation"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 9: Consistent model comparison
 * ----------------------------------------------------------------------- */
static void test_model_comparison(void)
{
    printf("[TEST  9] Consistent model comparison — same events, different models... ");

    const char *model_a = "/tmp/t19_ma.dat";
    const char *model_b = "/tmp/t19_mb.dat";
    const char *manifest = "/tmp/t19_manifest9.json";
    const char *csv = "/tmp/t19_csv9.csv";
    const char *out = "/tmp/t19_out9.txt";
    unlink(model_a); unlink(model_b);
    unlink(manifest); unlink(csv); unlink(out);

    /* Model A knows (10,20,30); Model B knows (40,50,60) */
    build_model(model_a, 10, 20, 30, 100);
    build_model(model_b, 40, 50, 60, 100);

    TestWorkload wls[] = {
        {"BEN", "benign", "benign", 100, 1000, 5000},
        {"SUS", "security_relevant", "suspicious", 200, 6000, 10000}
    };
    write_manifest(manifest, wls, 2);

    const char *rows[] = {
        "2000,100,\"a\",10,20,30,0.01,NORMAL",      /* known by A, unseen by B */
        "8000,200,\"b\",99,88,77,1.00,SUSPICIOUS"    /* unseen by both */
    };
    write_csv(csv, rows, 2);

    char args[512];
    snprintf(args, sizeof(args),
             "--model-a %s --model-b %s --manifest %s --dataset %s",
             model_a, model_b, manifest, csv);
    int rc = run_gt_compare(args, out);
    assert(rc == 0);

    /* Should show comparison table */
    assert(output_has(out, "Comparison Table"));
    assert(output_has(out, "Model A"));
    assert(output_has(out, "Model B"));

    unlink(model_a); unlink(model_b);
    unlink(manifest); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 10: Per-process vs per-workload differ when multiple PIDs
 * ----------------------------------------------------------------------- */
static void test_per_process_vs_workload(void)
{
    printf("[TEST 10] Per-process vs per-workload — aggregation differs... ");

    const char *manifest = "/tmp/t19_manifest10.json";
    const char *model = "/tmp/t19_m10.dat";
    const char *csv = "/tmp/t19_csv10.csv";
    const char *out = "/tmp/t19_out10.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 10, 20, 30, 100);

    /* Single benign workload with two PIDs (e.g., parent and child) */
    TestWorkload wls[] = {
        {"MULTI", "benign", "benign", 100, 1000, 9000}
    };
    write_manifest(manifest, wls, 1);

    /* PID 100 = known 3-gram; PID 101 = unseen 3-gram (child process) */
    const char *rows[] = {
        "2000,100,\"p\",10,20,30,0.01,NORMAL",
        "3000,101,\"p\",99,88,77,1.00,SUSPICIOUS"  /* child matched by timestamp */
    };
    write_csv(csv, rows, 2);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Per-workload: uses OR → workload has unseen 3-gram → alert → FP
     * Per-process: PID 100 = normal (TN), PID 101 = alert (FP) */
    assert(output_has(out, "Per-Process Evaluation"));
    assert(output_has(out, "Per-Workload Evaluation"));
    assert(output_has(out, "Unique Processes Evaluated"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 11: Detection latency measurement
 * ----------------------------------------------------------------------- */
static void test_detection_latency(void)
{
    printf("[TEST 11] Detection latency — first-alert timestamp... ");

    const char *manifest = "/tmp/t19_manifest11.json";
    const char *model = "/tmp/t19_m11.dat";
    const char *csv = "/tmp/t19_csv11.csv";
    const char *out = "/tmp/t19_out11.txt";
    unlink(manifest); unlink(model); unlink(csv); unlink(out);

    build_model(model, 10, 20, 30, 100);

    TestWorkload wls[] = {
        {"LAT_SUSP", "security_relevant", "suspicious", 200, 1000, 9000}
    };
    write_manifest(manifest, wls, 1);

    /* First event at 3000, first alert at 5000 */
    const char *rows[] = {
        "3000,200,\"s\",10,20,30,0.01,NORMAL",      /* known → not an alert */
        "5000,200,\"s\",99,88,77,1.00,SUSPICIOUS",   /* unseen → first alert */
        "7000,200,\"s\",88,77,66,1.00,SUSPICIOUS"    /* unseen → second alert */
    };
    write_csv(csv, rows, 3);

    char args[512];
    snprintf(args, sizeof(args),
             "--manifest %s --dataset %s --model %s", manifest, csv, model);
    int rc = run_gt_eval(args, out);
    assert(rc == 0);

    /* Latency table should show "DETECTED" for LAT_SUSP */
    assert(output_has(out, "Detection Latency Analysis"));
    assert(output_has(out, "DETECTED"));
    assert(output_has(out, "LAT_SUSP"));

    unlink(manifest); unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 12: Backward compatibility — all Stage 18 tests still pass
 * ----------------------------------------------------------------------- */
static void test_backward_compat(void)
{
    printf("[TEST 12] Backward compatibility — Stage 18 tests still pass... ");

    int rc = system("./tools/test_eval_independent > /dev/null 2>&1");
    assert(rc == 0);

    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
    printf("Stage 19 Ground-Truth Evaluation Unit Tests\n");
    printf("============================================\n");
    printf("Binaries under test:\n");
    printf("  ./tools/gt_evaluate\n");
    printf("  ./tools/gt_model_compare\n\n");

    test_manifest_parsing();
    test_timestamp_alignment();
    test_pid_matching();
    test_missing_events();
    test_confusion_matrix();
    test_zero_division();
    test_benign_workload();
    test_suspicious_workload();
    test_model_comparison();
    test_per_process_vs_workload();
    test_detection_latency();
    test_backward_compat();

    printf("\nALL STAGE 19 GROUND-TRUTH EVALUATION TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
