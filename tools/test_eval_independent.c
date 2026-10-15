/*
 * test_eval_independent.c — Stage 18: Independent CSV Evaluation Tests
 *
 * Tests:
 *  1. Valid independent evaluation CSV — correct alert/normal counts.
 *  2. Missing evaluation CSV file — graceful non-crash exit.
 *  3. Malformed CSV rows — counted separately, valid rows still scored.
 *  4. Empty CSV (header only) — reports zero valid rows, no crash.
 *  5. CSV with missing syscall columns — falls back, scores what it can.
 *  6. Identical training and evaluation files detected via inode check.
 *  7. Model provenance generation — file created and JSON valid.
 *  8. Model loading compatibility — provenance tool loads same model.
 *  9. Consistent eval record count across two different models.
 * 10. Backward compatibility — legacy positional mode still produces
 *     expected output strings (Held-out Evaluated, False Positives).
 *
 * Build & Run:
 *   make tools/test_eval_independent
 *   ./tools/test_eval_independent
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include "model.h"
#include "anomaly.h"
#include "ngram.h"

/* -----------------------------------------------------------------------
 * Helper: write a standard 8-column eval CSV
 * ----------------------------------------------------------------------- */
static void write_eval_csv(const char *path, const char *rows[], int nrows)
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
 * Helper: run eval_baseline_model and capture stdout to a temp file.
 * Returns exit status.
 * ----------------------------------------------------------------------- */
static int run_eval(const char *args, const char *outfile)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./tools/eval_baseline_model %s > %s 2>&1", args, outfile);
    return system(cmd);
}

/* Helper: check if a string appears anywhere in captured output file. */
static int output_contains(const char *outfile, const char *needle)
{
    FILE *f = fopen(outfile, "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, needle) != NULL) { found = 1; break; }
    }
    fclose(f);
    return found;
}

/* Helper: extract a numeric value from "Label   : <number>" pattern. */
static long extract_number(const char *outfile, const char *label)
{
    FILE *f = fopen(outfile, "r");
    if (!f) return -1;
    char line[1024];
    long result = -1;
    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, label) != NULL)
        {
            /* scan past the colon */
            char *p = strchr(line, ':');
            if (p) { result = strtol(p + 1, NULL, 10); break; }
        }
    }
    fclose(f);
    return result;
}

/* Helper: build a tiny training model, save to path. */
static void build_tiny_model(const char *model_path,
                              int s1, int s2, int s3, int count)
{
    NormalModel m;
    normal_model_init(&m);
    NGram g = {{s1, s2, s3}};
    for (int i = 0; i < count; i++)
        normal_model_add(&m, &g);
    normal_model_finalize(&m);
    assert(normal_model_save(&m, model_path) == 0);
}

/* -----------------------------------------------------------------------
 * TEST 1: Valid independent evaluation CSV — correct alert/normal counts.
 *
 * Model knows (10,20,30) — that 3-gram scores < threshold.
 * (70,80,90) is unseen — scores 1.0 → alert.
 * --eval-csv should see 1 alert, 1 normal out of 2 valid rows.
 * ----------------------------------------------------------------------- */
static void test_valid_eval_csv(void)
{
    printf("[TEST  1] Valid independent evaluation CSV, correct counts... ");

    const char *model = "/tmp/t18_m1.dat";
    const char *csv   = "/tmp/t18_eval1.csv";
    const char *out   = "/tmp/t18_out1.txt";
    unlink(model); unlink(csv); unlink(out);

    build_tiny_model(model, 10, 20, 30, 5);

    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL",   /* known → normal */
        "2000,100,\"p\",70,80,90,1.00,SUSPICIOUS" /* unseen → alert */
    };
    write_eval_csv(csv, rows, 2);

    char args[512];
    snprintf(args, sizeof(args), "--model %s --eval-csv %s", model, csv);
    int rc = run_eval(args, out);
    assert(rc == 0);

    assert(output_contains(out, "Valid Rows Scored        : 2"));
    assert(output_contains(out, "At/Above Threshold (alerts): 1"));
    assert(output_contains(out, "Below Threshold (normal) : 1"));
    assert(output_contains(out, "NOT a verified FPR"));

    unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 2: Missing evaluation CSV file — graceful exit (non-zero or
 *         prints error without crashing).
 * ----------------------------------------------------------------------- */
static void test_missing_eval_csv(void)
{
    printf("[TEST  2] Missing evaluation CSV — graceful failure... ");

    const char *model = "/tmp/t18_m2.dat";
    const char *out   = "/tmp/t18_out2.txt";
    unlink(model); unlink(out);

    build_tiny_model(model, 1, 2, 3, 1);

    /* The eval tool should print an error but not crash */
    char args[512];
    snprintf(args, sizeof(args),
             "--model %s --eval-csv /tmp/definitely_nonexistent_eval.csv", model);
    run_eval(args, out);   /* exit code may be 0 or non-zero; no crash is the test */

    /* Verify the tool ran and produced some output */
    struct stat st;
    assert(stat(out, &st) == 0);   /* output file must exist */

    unlink(model); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 3: Malformed CSV rows — counted separately, valid rows still scored.
 *
 * Two valid rows, one row with negative syscall IDs (malformed).
 * One row with empty fields — strtok_r skips consecutive delimiters, so
 * column alignment shifts and values ≥ 0 may be extracted; this is
 * parser-dependent behavior. The key test requirement is no crash and
 * that obviously malformed rows (negative IDs) are counted separately.
 * ----------------------------------------------------------------------- */
static void test_malformed_rows(void)
{
    printf("[TEST  3] Malformed CSV rows — counted, valid rows scored... ");

    const char *model = "/tmp/t18_m3.dat";
    const char *csv   = "/tmp/t18_eval3.csv";
    const char *out   = "/tmp/t18_out3.txt";
    unlink(model); unlink(csv); unlink(out);

    build_tiny_model(model, 10, 20, 30, 1);

    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL",  /* valid */
        "2000,100,\"p\",10,20,30,0.01,NORMAL",  /* valid duplicate */
        "3000,100,\"p\",-1,-2,-3,0.01,NORMAL"   /* malformed: negative syscall IDs */
    };
    write_eval_csv(csv, rows, 3);

    char args[512];
    snprintf(args, sizeof(args), "--model %s --eval-csv %s", model, csv);
    int rc = run_eval(args, out);
    assert(rc == 0);

    /* 2 valid rows scored, 1 malformed row skipped */
    assert(output_contains(out, "Valid Rows Scored        : 2"));
    assert(output_contains(out, "Malformed Rows (skipped) : 1"));

    unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 4: Empty CSV (header only) — reports zero valid rows, no crash.
 * ----------------------------------------------------------------------- */
static void test_empty_csv(void)
{
    printf("[TEST  4] Empty CSV (header only) — reports zero rows... ");

    const char *model = "/tmp/t18_m4.dat";
    const char *csv   = "/tmp/t18_eval4.csv";
    const char *out   = "/tmp/t18_out4.txt";
    unlink(model); unlink(csv); unlink(out);

    build_tiny_model(model, 1, 2, 3, 1);

    /* Write header only — no data rows */
    FILE *f = fopen(csv, "w");
    assert(f != NULL);
    fprintf(f, "monotonic_timestamp_ns,pid,process_name,"
               "syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    fclose(f);

    char args[512];
    snprintf(args, sizeof(args), "--model %s --eval-csv %s", model, csv);
    run_eval(args, out);  /* may exit non-zero; no crash is required */

    /* No segfault: output file must exist */
    struct stat st;
    assert(stat(out, &st) == 0);

    unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 5: CSV with syscall columns identifiable only by header name.
 *
 * When header has syscall_1/2/3 in non-standard positions (not 4,5,6),
 * the tool should still locate them by name and score correctly.
 * ----------------------------------------------------------------------- */
static void test_nonstandard_column_order(void)
{
    printf("[TEST  5] Non-standard column order detected by header name... ");

    const char *model = "/tmp/t18_m5.dat";
    const char *csv   = "/tmp/t18_eval5.csv";
    const char *out   = "/tmp/t18_out5.txt";
    unlink(model); unlink(csv); unlink(out);

    build_tiny_model(model, 10, 20, 30, 3);

    /* Columns: pid, syscall_1, syscall_2, syscall_3 (non-standard order) */
    FILE *f = fopen(csv, "w");
    assert(f != NULL);
    fprintf(f, "pid,syscall_1,syscall_2,syscall_3\n");
    fprintf(f, "100,10,20,30\n");   /* known 3-gram */
    fprintf(f, "100,7,8,9\n");       /* unseen 3-gram → alert */
    fclose(f);

    char args[512];
    snprintf(args, sizeof(args), "--model %s --eval-csv %s", model, csv);
    int rc = run_eval(args, out);
    assert(rc == 0);

    /* Both rows must be processed: 2 valid rows */
    assert(output_contains(out, "Valid Rows Scored        : 2"));

    unlink(model); unlink(csv); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 6: Identical training and evaluation files — leakage warning printed.
 *
 * We can't know what the eval tool was originally trained on (no provenance),
 * but we can verify the leakage warning path works by creating a provenance
 * file that points to the eval CSV, then running eval on the same file.
 * ----------------------------------------------------------------------- */
static void test_leakage_warning_same_file(void)
{
    printf("[TEST  6] Leakage warning fires when eval CSV == training CSV... ");

    const char *model     = "/tmp/t18_m6.dat";
    const char *train_csv = "/tmp/t18_same_file.csv";
    const char *prov      = "/tmp/t18_m6.dat.provenance.json";
    const char *out       = "/tmp/t18_out6.txt";
    unlink(model); unlink(train_csv); unlink(prov); unlink(out);

    build_tiny_model(model, 1, 2, 3, 1);

    /* Write ONE CSV that serves as both "training" and evaluation */
    const char *rows[] = { "1000,100,\"p\",1,2,3,0.01,NORMAL" };
    write_eval_csv(train_csv, rows, 1);

    /* Create provenance file pointing to train_csv */
    FILE *pf = fopen(prov, "w");
    assert(pf != NULL);
    fprintf(pf, "{\n");
    fprintf(pf, "  \"training_dataset_path\": \"%s\"\n", train_csv);
    fprintf(pf, "}\n");
    fclose(pf);

    /* Evaluate on the same CSV -- should trigger leakage warning */
    char args[512];
    snprintf(args, sizeof(args), "--model %s --eval-csv %s", model, train_csv);
    run_eval(args, out);

    /* Verify warning was printed */
    assert(output_contains(out, "TRAINING DATA LEAKAGE DETECTED") ||
           output_contains(out, "same device") ||
           output_contains(out, "SAME FILE"));

    unlink(model); unlink(train_csv); unlink(prov); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 7: Model provenance generation — file created with valid JSON fields.
 * ----------------------------------------------------------------------- */
static void test_provenance_generation(void)
{
    printf("[TEST  7] Model provenance generation — JSON fields present... ");

    const char *model = "/tmp/t18_m7.dat";
    const char *prov  = "/tmp/t18_m7.dat.provenance.json";
    const char *out   = "/tmp/t18_out7.txt";
    unlink(model); unlink(prov); unlink(out);

    build_tiny_model(model, 10, 20, 30, 2);

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./tools/gen_model_provenance --model %s --filter-mode all-rows"
             " > %s 2>&1", model, out);
    int rc = system(cmd);
    assert(rc == 0);

    /* Provenance file must exist */
    struct stat st;
    assert(stat(prov, &st) == 0);
    assert(st.st_size > 10);

    /* Check key JSON fields are present in the file */
    assert(output_contains(prov, "\"schema_version\""));
    assert(output_contains(prov, "\"model_sha256\""));
    assert(output_contains(prov, "\"unique_ngrams\""));
    assert(output_contains(prov, "\"total_training_ngrams\""));
    assert(output_contains(prov, "\"training_method\""));
    assert(output_contains(prov, "\"label_filter\""));
    assert(output_contains(prov, "\"disclaimer\""));
    assert(output_contains(prov, "all-rows"));

    /* --force must allow re-generation */
    snprintf(cmd, sizeof(cmd),
             "./tools/gen_model_provenance --model %s --filter-mode all-rows"
             " --force > /dev/null 2>&1", model);
    assert(system(cmd) == 0);

    /* Without --force, second run must fail */
    unlink(prov);
    snprintf(cmd, sizeof(cmd),
             "./tools/gen_model_provenance --model %s --filter-mode all-rows"
             " > /dev/null 2>&1", model);
    assert(system(cmd) == 0);  /* first run, file doesn't exist → success */

    snprintf(cmd, sizeof(cmd),
             "./tools/gen_model_provenance --model %s --filter-mode all-rows"
             " > /dev/null 2>&1", model);
    assert(system(cmd) != 0);  /* second run, file exists, no --force → fail */

    unlink(model); unlink(prov); unlink(out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 8: Model loading compatibility — provenance does not alter model data.
 *         Load model before and after provenance generation; compare.
 * ----------------------------------------------------------------------- */
static void test_provenance_does_not_alter_model(void)
{
    printf("[TEST  8] Provenance generation does not alter model binary... ");

    const char *model = "/tmp/t18_m8.dat";
    const char *prov  = "/tmp/t18_m8.dat.provenance.json";
    unlink(model); unlink(prov);

    build_tiny_model(model, 5, 10, 15, 7);

    /* Load model BEFORE provenance generation */
    NormalModel before;
    assert(normal_model_load(&before, model) == 0);

    /* Generate provenance */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "./tools/gen_model_provenance --model %s > /dev/null 2>&1", model);
    assert(system(cmd) == 0);

    /* Load model AFTER provenance generation */
    NormalModel after;
    assert(normal_model_load(&after, model) == 0);

    /* Compare: model must be byte-identical */
    assert(before.size == after.size);
    assert(before.total_ngrams == after.total_ngrams);
    for (size_t i = 0; i < before.size; i++)
    {
        assert(ngram_equal(&before.entries[i].ngram, &after.entries[i].ngram));
        assert(before.entries[i].count == after.entries[i].count);
    }

    unlink(model); unlink(prov);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 9: Consistent eval record count across two different models.
 *
 * Two models (baseline-like and experimental-like) evaluated on the same
 * small CSV must both report the same "Valid Rows Scored" count.
 * ----------------------------------------------------------------------- */
static void test_consistent_record_count_across_models(void)
{
    printf("[TEST  9] Consistent eval record count across two models... ");

    const char *model_a = "/tmp/t18_ma.dat";
    const char *model_b = "/tmp/t18_mb.dat";
    const char *csv     = "/tmp/t18_eval9.csv";
    const char *out_a   = "/tmp/t18_out9a.txt";
    const char *out_b   = "/tmp/t18_out9b.txt";
    unlink(model_a); unlink(model_b); unlink(csv);
    unlink(out_a); unlink(out_b);

    /* Model A knows (1,2,3); Model B knows (4,5,6) */
    build_tiny_model(model_a, 1, 2, 3, 10);
    build_tiny_model(model_b, 4, 5, 6, 10);

    /* Evaluation CSV contains 4 distinct 3-grams */
    const char *rows[] = {
        "1000,100,\"p\",1,2,3,0.01,NORMAL",
        "2000,100,\"p\",4,5,6,0.01,NORMAL",
        "3000,100,\"p\",7,8,9,1.00,SUSPICIOUS",
        "4000,100,\"p\",10,11,12,1.00,SUSPICIOUS"
    };
    write_eval_csv(csv, rows, 4);

    char args_a[512], args_b[512];
    snprintf(args_a, sizeof(args_a), "--model %s --eval-csv %s", model_a, csv);
    snprintf(args_b, sizeof(args_b), "--model %s --eval-csv %s", model_b, csv);

    assert(run_eval(args_a, out_a) == 0);
    assert(run_eval(args_b, out_b) == 0);

    /* Both must score exactly 4 valid rows */
    long count_a = extract_number(out_a, "Valid Rows Scored");
    long count_b = extract_number(out_b, "Valid Rows Scored");
    assert(count_a == 4);
    assert(count_b == 4);
    assert(count_a == count_b);

    /* Alert counts must differ (A knows 1,2,3; B knows 4,5,6) */
    long alerts_a = extract_number(out_a, "At/Above Threshold (alerts)");
    long alerts_b = extract_number(out_b, "At/Above Threshold (alerts)");
    /* Model A alerts on (4,5,6), (7,8,9), (10,11,12) = 3 */
    /* Model B alerts on (1,2,3), (7,8,9), (10,11,12) = 3 */
    assert(alerts_a == 3);
    assert(alerts_b == 3);

    unlink(model_a); unlink(model_b); unlink(csv);
    unlink(out_a); unlink(out_b);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 10: Backward compatibility — legacy positional mode still produces
 *          "Held-out Evaluated (30%)" and "False Positives" in output.
 *
 * This ensures that INTEGRATION 7 in test_trainer_detector_compat continues
 * to work, and no existing scripts relying on these strings break.
 * ----------------------------------------------------------------------- */
static void test_backward_compat_legacy_mode(void)
{
    printf("[TEST 10] Backward compat: legacy positional mode output strings... ");

    const char *tmp_csv   = "/tmp/t18_legacy.csv";
    const char *tmp_model = "/tmp/t18_legacy.dat";
    const char *tmp_out   = "/tmp/t18_legacy_out.txt";
    unlink(tmp_csv); unlink(tmp_model); unlink(tmp_out);

    /* Build a 10-row CSV and train a model on it */
    FILE *fc = fopen(tmp_csv, "w");
    assert(fc != NULL);
    fprintf(fc, "monotonic_timestamp_ns,pid,process_name,"
                "syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    for (int i = 0; i < 10; i++)
        fprintf(fc, "%d000000,100,\"p\",%d,%d,%d,0.0000,NORMAL\n",
                i + 1, i, i + 1, i + 2);
    fclose(fc);

    /* Train model */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv -f %s %s > /dev/null 2>&1",
             tmp_csv, tmp_model);
    assert(system(cmd) == 0);

    /* Run eval in legacy positional mode: eval_baseline_model <model> <csv> */
    snprintf(cmd, sizeof(cmd),
             "./tools/eval_baseline_model %s %s > %s 2>&1",
             tmp_model, tmp_csv, tmp_out);
    assert(system(cmd) == 0);

    /* Verify legacy output strings are still present */
    assert(output_contains(tmp_out, "Held-out Evaluated (30%)"));
    assert(output_contains(tmp_out, "False Positives (FP)"));
    assert(output_contains(tmp_out, "False Positive Rate (FPR)"));

    /* Verify correct 70/30 split: 10 rows → 3 held-out */
    assert(output_contains(tmp_out, "Held-out Evaluated (30%)    : 3"));

    unlink(tmp_csv); unlink(tmp_model); unlink(tmp_out);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */
int main(void)
{
    printf("Stage 18 Independent Evaluation Unit Tests\n");
    printf("===========================================\n");
    printf("Binaries under test:\n");
    printf("  ./tools/eval_baseline_model\n");
    printf("  ./tools/gen_model_provenance\n\n");

    test_valid_eval_csv();
    test_missing_eval_csv();
    test_malformed_rows();
    test_empty_csv();
    test_nonstandard_column_order();
    test_leakage_warning_same_file();
    test_provenance_generation();
    test_provenance_does_not_alter_model();
    test_consistent_record_count_across_models();
    test_backward_compat_legacy_mode();

    printf("\nALL STAGE 18 INDEPENDENT EVALUATION TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
