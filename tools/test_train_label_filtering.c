/*
 * test_train_label_filtering.c — Stage 17 unit tests for --normal-only label filtering
 *
 * Tests:
 * 1. Default training behavior: trains on ALL rows (NORMAL + SUSPICIOUS).
 * 2. --normal-only: trains only on NORMAL-labelled rows.
 * 3. --normal-only: SUSPICIOUS rows are excluded (not in model).
 * 4. Missing predicted_label column with --normal-only: all rows excluded safely.
 * 5. Invalid / blank label with --normal-only: row excluded, not malformed.
 * 6. Model save/load round-trip: models produced remain binary-compatible.
 * 7. --force flag still works alongside --normal-only.
 * 8. baseline_model.dat and normal_model.dat overwrite protection still active.
 * 9. Existing explanation and compat tests are unaffected (smoke test).
 *
 * Build & Run:
 *   make tools/test_train_label_filtering
 *   ./tools/test_train_label_filtering
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "model.h"
#include "anomaly.h"
#include "ngram.h"

/* -----------------------------------------------------------------------
 * Helper: write a temporary CSV with the standard 8-column live format.
 * Rows is a NULL-terminated array of strings (one data row each).
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

/* Helper: run train_from_csv with given extra_args and return exit status */
static int run_trainer(const char *extra_args, const char *csv, const char *model)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv %s %s %s > /tmp/tfc_out.txt 2>&1",
             extra_args, csv, model);
    return system(cmd);
}

/* -----------------------------------------------------------------------
 * TEST 1: Default mode (no --normal-only) trains on ALL rows.
 * Expect both NORMAL and SUSPICIOUS 3-grams to appear in model.
 * ----------------------------------------------------------------------- */
static void test_default_trains_all(void)
{
    printf("[TEST 1] Default mode trains on ALL rows (NORMAL + SUSPICIOUS)... ");

    const char *csv  = "/tmp/tfc_test1.csv";
    const char *mdat = "/tmp/tfc_test1.dat";
    unlink(csv); unlink(mdat);

    /* Two NORMAL rows, one SUSPICIOUS row — all have distinct 3-grams */
    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL",
        "2000,100,\"p\",40,50,60,0.01,NORMAL",
        "3000,100,\"p\",70,80,90,1.00,SUSPICIOUS"
    };
    write_csv(csv, rows, 3);

    int rc = run_trainer("", csv, mdat);
    assert(rc == 0);

    NormalModel model;
    assert(normal_model_load(&model, mdat) == 0);
    /* All 3 unique 3-grams should be present */
    assert(model.size == 3);
    assert(model.total_ngrams == 3);

    /* Verify the SUSPICIOUS 3-gram (70,80,90) IS present in default mode */
    NGram sus = {{70, 80, 90}};
    double score = anomaly_score(&model, &sus);
    assert(score < ANOMALY_THRESHOLD);  /* known → not flagged */

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 2: --normal-only trains ONLY on NORMAL rows.
 * ----------------------------------------------------------------------- */
static void test_normal_only_accepts_normal(void)
{
    printf("[TEST 2] --normal-only accepts NORMAL rows... ");

    const char *csv  = "/tmp/tfc_test2.csv";
    const char *mdat = "/tmp/tfc_test2.dat";
    unlink(csv); unlink(mdat);

    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL",
        "2000,100,\"p\",40,50,60,0.01,NORMAL"
    };
    write_csv(csv, rows, 2);

    int rc = run_trainer("--normal-only", csv, mdat);
    assert(rc == 0);

    NormalModel model;
    assert(normal_model_load(&model, mdat) == 0);
    assert(model.size == 2);     /* exactly 2 unique 3-grams */
    assert(model.total_ngrams == 2);

    /* Both known 3-grams score below threshold */
    NGram g1 = {{10, 20, 30}};
    NGram g2 = {{40, 50, 60}};
    assert(anomaly_score(&model, &g1) < ANOMALY_THRESHOLD);
    assert(anomaly_score(&model, &g2) < ANOMALY_THRESHOLD);

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 3: --normal-only EXCLUDES SUSPICIOUS rows.
 * ----------------------------------------------------------------------- */
static void test_normal_only_excludes_suspicious(void)
{
    printf("[TEST 3] --normal-only excludes SUSPICIOUS rows... ");

    const char *csv  = "/tmp/tfc_test3.csv";
    const char *mdat = "/tmp/tfc_test3.dat";
    unlink(csv); unlink(mdat);

    /* Mix: one NORMAL, one SUSPICIOUS.  Only the NORMAL 3-gram must appear. */
    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL",
        "2000,100,\"p\",70,80,90,1.00,SUSPICIOUS"
    };
    write_csv(csv, rows, 2);

    int rc = run_trainer("--normal-only", csv, mdat);
    assert(rc == 0);

    NormalModel model;
    assert(normal_model_load(&model, mdat) == 0);
    /* Only 1 entry: the NORMAL 3-gram */
    assert(model.size == 1);

    /* NORMAL 3-gram is known → score below threshold */
    NGram normal_ng = {{10, 20, 30}};
    assert(anomaly_score(&model, &normal_ng) < ANOMALY_THRESHOLD);

    /* SUSPICIOUS 3-gram is unseen → score == 1.0 → triggers alert */
    NGram sus_ng = {{70, 80, 90}};
    assert(anomaly_score(&model, &sus_ng) == 1.0);

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 4: Missing predicted_label column + --normal-only → all rows excluded.
 * The tool must NOT silently train on rows whose label cannot be verified.
 * ----------------------------------------------------------------------- */
static void test_normal_only_missing_label_col(void)
{
    printf("[TEST 4] --normal-only with missing label column excludes all rows... ");

    const char *csv  = "/tmp/tfc_test4.csv";
    const char *mdat = "/tmp/tfc_test4.dat";
    unlink(csv); unlink(mdat);

    /* Write CSV with only 6 columns (no predicted_label column) */
    FILE *f = fopen(csv, "w");
    assert(f != NULL);
    fprintf(f, "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3\n");
    fprintf(f, "1000,100,\"p\",10,20,30\n");
    fclose(f);

    /* Trainer should exit with non-zero because 0 n-grams were added */
    int rc = run_trainer("--normal-only", csv, mdat);
    assert(rc != 0);   /* expected: "Error: No valid 3-grams extracted" */
    assert(access(mdat, F_OK) != 0);  /* no model file created */

    unlink(csv);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 5: Blank / invalid label with --normal-only → row excluded, not
 *         counted as malformed (structural columns are still valid).
 *         One valid NORMAL row must ensure model is saved.
 * ----------------------------------------------------------------------- */
static void test_normal_only_invalid_label_excluded(void)
{
    printf("[TEST 5] --normal-only excludes blank/invalid labels safely... ");

    const char *csv  = "/tmp/tfc_test5.csv";
    const char *mdat = "/tmp/tfc_test5.dat";
    unlink(csv); unlink(mdat);

    /* Row with label "UNKNOWN" is not NORMAL → excluded */
    /* Row with empty label is not NORMAL → excluded */
    /* Row with label "NORMAL" is accepted */
    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,UNKNOWN",
        "2000,100,\"p\",40,50,60,0.01,",
        "3000,100,\"p\",70,80,90,0.01,NORMAL"
    };
    write_csv(csv, rows, 3);

    int rc = run_trainer("--normal-only", csv, mdat);
    assert(rc == 0);

    NormalModel model;
    assert(normal_model_load(&model, mdat) == 0);
    /* Only the NORMAL row => 1 unique 3-gram */
    assert(model.size == 1);

    NGram normal_ng = {{70, 80, 90}};
    assert(anomaly_score(&model, &normal_ng) < ANOMALY_THRESHOLD);

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 6: Save/load round-trip for a --normal-only produced model.
 * Verifies binary format compatibility with normal_model_load().
 * ----------------------------------------------------------------------- */
static void test_model_save_load_compat(void)
{
    printf("[TEST 6] Model save/load round-trip compatibility... ");

    const char *csv  = "/tmp/tfc_test6.csv";
    const char *mdat = "/tmp/tfc_test6.dat";
    unlink(csv); unlink(mdat);

    const char *rows[] = {
        "1000,100,\"p\",1,2,3,0.01,NORMAL",
        "2000,100,\"p\",1,2,3,0.01,NORMAL",   /* duplicate → count=2 */
        "3000,100,\"p\",4,5,6,0.01,NORMAL",
        "4000,100,\"p\",7,8,9,1.00,SUSPICIOUS" /* excluded */
    };
    write_csv(csv, rows, 4);

    assert(run_trainer("--normal-only", csv, mdat) == 0);

    NormalModel m1;
    assert(normal_model_load(&m1, mdat) == 0);
    assert(m1.size == 2);
    assert(m1.total_ngrams == 3);

    /* Reload a second time and compare */
    NormalModel m2;
    assert(normal_model_load(&m2, mdat) == 0);
    assert(m2.size == m1.size);
    assert(m2.total_ngrams == m1.total_ngrams);
    for (size_t i = 0; i < m1.size; i++)
    {
        assert(ngram_equal(&m1.entries[i].ngram, &m2.entries[i].ngram));
        assert(m1.entries[i].count == m2.entries[i].count);
    }

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 7: --force combined with --normal-only overwrites existing model.
 * ----------------------------------------------------------------------- */
static void test_force_combined_with_normal_only(void)
{
    printf("[TEST 7] --force combined with --normal-only overwrites model... ");

    const char *csv  = "/tmp/tfc_test7.csv";
    const char *mdat = "/tmp/tfc_test7.dat";
    unlink(csv); unlink(mdat);

    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL"
    };
    write_csv(csv, rows, 1);

    /* First run creates the model */
    assert(run_trainer("--normal-only", csv, mdat) == 0);

    /* Second run without --force must fail */
    int rc = run_trainer("--normal-only", csv, mdat);
    assert(rc != 0);

    /* Third run with --force must succeed */
    assert(run_trainer("--normal-only -f", csv, mdat) == 0);

    NormalModel model;
    assert(normal_model_load(&model, mdat) == 0);
    assert(model.size == 1);

    unlink(csv); unlink(mdat);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 8: Overwrite protection: normal_model.dat and baseline_model.dat.
 * ----------------------------------------------------------------------- */
static void test_overwrite_protection(void)
{
    printf("[TEST 8] Core model overwrite protection (normal + baseline)... ");

    const char *csv = "/tmp/tfc_test8.csv";
    unlink(csv);

    const char *rows[] = {
        "1000,100,\"p\",10,20,30,0.01,NORMAL"
    };
    write_csv(csv, rows, 1);

    char cmd[512];

    /* Attempt to write to normal_model.dat → must fail */
    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv %s normal_model.dat > /dev/null 2>&1", csv);
    assert(system(cmd) != 0);

    /* Attempt to write to baseline_model.dat → must fail */
    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv %s baseline_model.dat > /dev/null 2>&1", csv);
    assert(system(cmd) != 0);

    /* Same checks combined with --normal-only */
    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv --normal-only %s normal_model.dat > /dev/null 2>&1", csv);
    assert(system(cmd) != 0);

    snprintf(cmd, sizeof(cmd),
             "./tools/train_from_csv --normal-only %s baseline_model.dat > /dev/null 2>&1", csv);
    assert(system(cmd) != 0);

    unlink(csv);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 9: Smoke test — existing tests still compile and pass.
 * Invokes the existing test_trainer_detector_compat binary.
 * ----------------------------------------------------------------------- */
static void test_existing_compat_smoke(void)
{
    printf("[TEST 9] Smoke test: existing trainer-detector compat tests pass... ");
    int rc = system("./tools/test_trainer_detector_compat > /dev/null 2>&1");
    assert(rc == 0);
    printf("PASSED\n");
}

/* -----------------------------------------------------------------------
 * TEST 10: Smoke test — existing explanation tests still pass.
 * ----------------------------------------------------------------------- */
static void test_existing_explanation_smoke(void)
{
    printf("[TEST 10] Smoke test: existing explanation unit tests pass... ");
    int rc = system("./tools/test_explanation > /dev/null 2>&1");
    assert(rc == 0);
    printf("PASSED\n");
}

int main(void)
{
    printf("Stage 17 Label Filtering Unit Tests\n");
    printf("====================================\n");
    printf("Binary under test: ./tools/train_from_csv\n\n");

    test_default_trains_all();
    test_normal_only_accepts_normal();
    test_normal_only_excludes_suspicious();
    test_normal_only_missing_label_col();
    test_normal_only_invalid_label_excluded();
    test_model_save_load_compat();
    test_force_combined_with_normal_only();
    test_overwrite_protection();
    test_existing_compat_smoke();
    test_existing_explanation_smoke();

    printf("\nALL STAGE 17 LABEL FILTERING TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
