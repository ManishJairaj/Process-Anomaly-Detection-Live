/*
 * test_trainer_detector_compat.c — Integration test for Trainer-to-Detector path
 *
 * Verifies:
 * 1. Building a benign model using normal_model_init(), normal_model_add(), normal_model_finalize().
 * 2. Saving via normal_model_save() and loading via normal_model_load() (exact detector path).
 * 3. Live scoring behavior via anomaly_score() and anomaly_is_suspicious():
 *    - Known/seen 3-grams score <= 0.50 -> anomaly_is_suspicious() == 0 (NORMAL)
 *    - Unknown/unseen 3-grams score == 1.0 -> anomaly_is_suspicious() == 1 (SUSPICIOUS)
 * 4. Safe failure behavior on missing files or corrupted binary models.
 *
 * Build & Run:
 *   gcc -Wall -Wextra -O2 -Iinclude -o tools/test_trainer_detector_compat \
 *       tools/test_trainer_detector_compat.c src/event.c src/ngram.c src/window.c src/model.c src/anomaly.c src/explanation.c -lm
 *   ./tools/test_trainer_detector_compat
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "model.h"
#include "anomaly.h"

static void test_trainer_detector_pipeline(void)
{
    printf("[INTEGRATION 1] Trainer-to-Detector Serialization & Scoring... ");
    const char *tmpfile = "/tmp/test_trainer_detector.dat";

    NormalModel trainer_model;
    normal_model_init(&trainer_model);

    /* Simulate benign training: add known Linux syscall 3-grams */
    NGram benign_1 = {{0, 1, 2}}; /* read, write, open */
    NGram benign_2 = {{2, 3, 9}}; /* open, close, mmap */

    assert(normal_model_add(&trainer_model, &benign_1) == 0);
    assert(normal_model_add(&trainer_model, &benign_1) == 0); /* count = 2 */
    assert(normal_model_add(&trainer_model, &benign_2) == 0); /* count = 1 */
    normal_model_finalize(&trainer_model);

    /* Save model snapshot (Trainer step) */
    assert(normal_model_save(&trainer_model, tmpfile) == 0);

    /* Load model snapshot (Detector step) */
    NormalModel detector_model;
    assert(normal_model_load(&detector_model, tmpfile) == 0);
    assert(detector_model.size == 2);
    assert(detector_model.total_ngrams == 3);

    /* Evaluate live event scoring semantics */
    /* 1. Benign 3-gram (seen) */
    double score_benign = anomaly_score(&detector_model, &benign_1);
    assert(score_benign <= 0.50);
    assert(anomaly_is_suspicious(score_benign) == 0);

    /* 2. Anomaly 3-gram (unseen) */
    NGram malicious = {{999, 888, 777}};
    double score_malicious = anomaly_score(&detector_model, &malicious);
    assert(score_malicious == 1.0);
    assert(anomaly_is_suspicious(score_malicious) == 1);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_missing_file(void)
{
    printf("[INTEGRATION 2] Missing Model File Clean Failure... ");
    NormalModel model;
    int rc = normal_model_load(&model, "/tmp/definitely_nonexistent_model.dat");
    assert(rc != 0);
    assert(model.size == 0);
    assert(model.total_ngrams == 0);
    printf("PASSED\n");
}

static void test_invalid_entry_count_zero(void)
{
    printf("[INTEGRATION 3] Rejection of Invalid Zero Count Entry... ");
    const char *tmpfile = "/tmp/test_invalid_zero_count.dat";

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = 3;
    header.entry_count = 1;
    header.total_ngrams = 1;

    ModelEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.ngram.values[0] = 1;
    entry.ngram.values[1] = 2;
    entry.ngram.values[2] = 3;
    entry.count = 0; /* Invalid count = 0 */

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&header, sizeof(ModelHeader), 1, f) == 1);
    assert(fwrite(&entry, sizeof(ModelEntry), 1, f) == 1);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);
    assert(model.size == 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_negative_syscall_id(void)
{
    printf("[INTEGRATION 4] Rejection of Negative Syscall ID... ");
    const char *tmpfile = "/tmp/test_negative_syscall.dat";

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = 3;
    header.entry_count = 1;
    header.total_ngrams = 1;

    ModelEntry entry;
    memset(&entry, 0, sizeof(entry));
    entry.ngram.values[0] = 1;
    entry.ngram.values[1] = -5; /* Invalid negative syscall ID */
    entry.ngram.values[2] = 3;
    entry.count = 1;

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&header, sizeof(ModelHeader), 1, f) == 1);
    assert(fwrite(&entry, sizeof(ModelEntry), 1, f) == 1);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);
    assert(model.size == 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_duplicate_entry(void)
{
    printf("[INTEGRATION 5] Rejection of Duplicate Entries... ");
    const char *tmpfile = "/tmp/test_duplicate_entry.dat";

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = 3;
    header.entry_count = 2;
    header.total_ngrams = 2;

    ModelEntry entries[2];
    memset(entries, 0, sizeof(entries));
    entries[0].ngram.values[0] = 1; entries[0].ngram.values[1] = 2; entries[0].ngram.values[2] = 3; entries[0].count = 1;
    entries[1].ngram.values[0] = 1; entries[1].ngram.values[1] = 2; entries[1].ngram.values[2] = 3; entries[1].count = 1; /* Duplicate */

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&header, sizeof(ModelHeader), 1, f) == 1);
    assert(fwrite(entries, sizeof(ModelEntry), 2, f) == 2);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);
    assert(model.size == 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_csv_trainer_overwrite_and_compat(void)
{
    printf("[INTEGRATION 6] CSV Trainer Overwrite Protection & Model Load... ");
    const char *tmp_csv = "/tmp/test_trainer_input.csv";
    const char *tmp_model = "/tmp/test_trainer_output.dat";

    unlink(tmp_csv);
    unlink(tmp_model);

    FILE *fc = fopen(tmp_csv, "w");
    assert(fc != NULL);
    fprintf(fc, "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    fprintf(fc, "1000000,100,\"test_proc\",0,1,2,0.0000,NORMAL\n");
    fprintf(fc, "2000000,100,\"test_proc\",1,2,3,0.0000,NORMAL\n");
    fclose(fc);

    /* Run trainer command line */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "./tools/train_from_csv %s %s > /dev/null 2>&1", tmp_csv, tmp_model);
    int rc = system(cmd);
    assert(rc == 0);

    /* Verify model binary is valid */
    NormalModel model;
    assert(normal_model_load(&model, tmp_model) == 0);
    assert(model.size == 2);
    assert(model.total_ngrams == 2);

    /* Test overwrite safety: rerun without -f should fail */
    rc = system(cmd);
    assert(rc != 0);

    /* Rerun with -f should succeed */
    snprintf(cmd, sizeof(cmd), "./tools/train_from_csv -f %s %s > /dev/null 2>&1", tmp_csv, tmp_model);
    rc = system(cmd);
    assert(rc == 0);

    unlink(tmp_csv);
    unlink(tmp_model);
    printf("PASSED\n");
}

static void test_dynamic_eval_split(void)
{
    printf("[INTEGRATION 7] Dynamic 70/30 Split Non-Empty Held-Out Validation... ");
    const char *tmp_csv = "/tmp/test_split_input.csv";
    const char *tmp_model = "/tmp/test_split_output.dat";
    const char *tmp_out = "/tmp/test_eval_output.txt";

    unlink(tmp_csv);
    unlink(tmp_model);
    unlink(tmp_out);

    FILE *fc = fopen(tmp_csv, "w");
    assert(fc != NULL);
    fprintf(fc, "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
    for (int i = 0; i < 10; i++)
    {
        fprintf(fc, "%d000000,100,\"test_proc\",%d,%d,%d,0.0000,NORMAL\n", i + 1, i, i + 1, i + 2);
    }
    fclose(fc);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "./tools/train_from_csv -f %s %s > /dev/null 2>&1", tmp_csv, tmp_model);
    assert(system(cmd) == 0);

    snprintf(cmd, sizeof(cmd), "./tools/eval_baseline_model %s %s > %s 2>&1", tmp_model, tmp_csv, tmp_out);
    assert(system(cmd) == 0);

    FILE *fo = fopen(tmp_out, "r");
    assert(fo != NULL);
    char line[512];
    int found_heldout = 0;
    while (fgets(line, sizeof(line), fo))
    {
        if (strstr(line, "Held-out Evaluated (30%)    : 3") != NULL)
        {
            found_heldout = 1;
        }
    }
    fclose(fo);

    assert(found_heldout == 1);

    unlink(tmp_csv);
    unlink(tmp_model);
    unlink(tmp_out);
    printf("PASSED\n");
}

int main(void)
{
    printf("Running Trainer-to-Detector End-to-End Compatibility Tests\n");
    printf("========================================================\n");

    test_trainer_detector_pipeline();
    test_missing_file();
    test_invalid_entry_count_zero();
    test_negative_syscall_id();
    test_duplicate_entry();
    test_csv_trainer_overwrite_and_compat();
    test_dynamic_eval_split();

    printf("\nALL INTEGRATION TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
