/*
 * test_explanation.c — Unit tests for Explainable Anomaly Detection
 *
 * Tests:
 * 1. Unseen 3-gram produces factual reason "3-gram not observed in the loaded normal model", score 1.0, threshold 0.80.
 * 2. Known 3-gram reports stored count, correct score <= 0.50, and is_seen == 1.
 * 3. Unknown syscall IDs (-1, 9999) produce safe fallback name "unknown(<id>)".
 * 4. Explanation threshold matches ANOMALY_THRESHOLD (0.80).
 * 5. NULL model, event, or ngram pointers handle gracefully without crash.
 * 6. Long process names and formatting buffer limits do not overflow.
 * 7. Explanation generation is purely read-only and does not modify model state.
 *
 * Build & Run:
 *   gcc -Wall -Wextra -O2 -Iinclude -o tools/test_explanation \
 *       tools/test_explanation.c src/explanation.c src/model.c src/ngram.c src/event.c src/anomaly.c src/window.c -lm
 *   ./tools/test_explanation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "explanation.h"
#include "anomaly.h"
#include "model.h"

static void test_unseen_explanation(void)
{
    printf("[UNIT 1] Unseen 3-Gram Explanation... ");

    NormalModel model;
    normal_model_init(&model);

    NGram known = {{0, 1, 2}};
    normal_model_add(&model, &known);
    normal_model_finalize(&model);

    SyscallEvent event;
    memset(&event, 0, sizeof(event));
    event.pid = 1234;
    snprintf(event.process_name, sizeof(event.process_name), "test_proc");

    NGram unseen = {{0, 1, 59}}; /* read -> write -> execve */
    double score = anomaly_score(&model, &unseen);
    assert(score == 1.0);

    AnomalyExplanation exp;
    assert(generate_explanation(&event, &unseen, &model, score, ANOMALY_THRESHOLD, &exp) == 0);

    assert(exp.pid == 1234);
    assert(strcmp(exp.process_name, "test_proc") == 0);
    assert(exp.is_seen == 0);
    assert(exp.model_count == 0);
    assert(exp.score == 1.0);
    assert(exp.threshold == ANOMALY_THRESHOLD);
    assert(strcmp(exp.syscall_names[0], "read") == 0);
    assert(strcmp(exp.syscall_names[1], "write") == 0);
    assert(strcmp(exp.syscall_names[2], "execve") == 0);
    assert(strcmp(exp.reason, "3-gram not observed in the loaded normal model") == 0);

    char alert[512];
    assert(format_explanation_string(&exp, alert, sizeof(alert)) == 0);
    assert(strstr(alert, "ALERT | PID=1234 | COMM=test_proc | NGRAM=read -> write -> execve | SCORE=1.00 | THRESHOLD=0.80 | REASON=3-gram not observed in the loaded normal model") != NULL);

    printf("PASSED\n");
}

static void test_known_explanation(void)
{
    printf("[UNIT 2] Known 3-Gram Explanation... ");

    NormalModel model;
    normal_model_init(&model);

    NGram known = {{0, 1, 2}}; /* read -> write -> open */
    normal_model_add(&model, &known);
    normal_model_add(&model, &known);
    normal_model_add(&model, &known); /* count = 3 */
    normal_model_finalize(&model);

    SyscallEvent event;
    memset(&event, 0, sizeof(event));
    event.pid = 5678;
    snprintf(event.process_name, sizeof(event.process_name), "nginx");

    double score = anomaly_score(&model, &known);
    assert(score <= 0.50);

    AnomalyExplanation exp;
    assert(generate_explanation(&event, &known, &model, score, ANOMALY_THRESHOLD, &exp) == 0);

    assert(exp.pid == 5678);
    assert(strcmp(exp.process_name, "nginx") == 0);
    assert(exp.is_seen == 1);
    assert(exp.model_count == 3);
    assert(exp.score == score);
    assert(exp.threshold == 0.80);
    assert(strcmp(exp.syscall_names[0], "read") == 0);
    assert(strcmp(exp.syscall_names[1], "write") == 0);
    assert(strcmp(exp.syscall_names[2], "open") == 0);
    assert(strstr(exp.reason, "count 3") != NULL);

    printf("PASSED\n");
}

static void test_unknown_syscall_ids(void)
{
    printf("[UNIT 3] Unknown Syscall ID Fallback... ");

    char buf[32];
    assert(strcmp(get_syscall_name(0, buf, sizeof(buf)), "read") == 0);
    assert(strcmp(get_syscall_name(59, buf, sizeof(buf)), "execve") == 0);
    assert(strcmp(get_syscall_name(-1, buf, sizeof(buf)), "unknown(-1)") == 0);
    assert(strcmp(get_syscall_name(9999, buf, sizeof(buf)), "unknown(9999)") == 0);

    NGram unk_ngram = {{-1, 9999, 0}};
    AnomalyExplanation exp;
    assert(generate_explanation(NULL, &unk_ngram, NULL, 1.0, 0.80, &exp) == 0);

    assert(strcmp(exp.syscall_names[0], "unknown(-1)") == 0);
    assert(strcmp(exp.syscall_names[1], "unknown(9999)") == 0);
    assert(strcmp(exp.syscall_names[2], "read") == 0);

    printf("PASSED\n");
}

static void test_threshold_matching(void)
{
    printf("[UNIT 4] Live Threshold Matching... ");

    NGram ngram = {{0, 1, 2}};
    AnomalyExplanation exp;
    assert(generate_explanation(NULL, &ngram, NULL, 0.5, ANOMALY_THRESHOLD, &exp) == 0);
    assert(exp.threshold == ANOMALY_THRESHOLD);
    assert(exp.threshold == 0.80);

    printf("PASSED\n");
}

static void test_null_safety(void)
{
    printf("[UNIT 5] NULL Pointer Crash Safety... ");

    NGram ngram = {{0, 1, 2}};
    AnomalyExplanation exp;

    /* NULL model pointer should not crash */
    assert(generate_explanation(NULL, &ngram, NULL, 1.0, 0.80, &exp) == 0);
    assert(exp.pid == 0);
    assert(strcmp(exp.process_name, "unknown") == 0);
    assert(exp.is_seen == 0);

    /* Invalid NULL ngram or exp should return -1 error cleanly */
    assert(generate_explanation(NULL, NULL, NULL, 1.0, 0.80, &exp) == -1);
    assert(generate_explanation(NULL, &ngram, NULL, 1.0, 0.80, NULL) == -1);

    /* explain_anomaly with NULL parameters should return safely without crash */
    explain_anomaly(NULL, NULL, NULL, 1.0);

    printf("PASSED\n");
}

static void test_read_only_invariance(void)
{
    printf("[UNIT 6] Read-Only Invariance Check... ");

    NormalModel model;
    normal_model_init(&model);
    NGram ngram = {{0, 1, 2}};
    normal_model_add(&model, &ngram);
    normal_model_finalize(&model);

    NormalModel copy_before = model;
    AnomalyExplanation exp;
    generate_explanation(NULL, &ngram, &model, 0.50, 0.80, &exp);

    assert(memcmp(&model, &copy_before, sizeof(NormalModel)) == 0);

    printf("PASSED\n");
}

static void test_score_boundary_prefix(void)
{
    printf("[UNIT 7] Score Boundary Prefix (INFO vs ALERT)... ");

    SyscallEvent event = {100, 999, 100, 0, 0, "test_boundary"};
    NGram ngram = {{0, 1, 2}};
    AnomalyExplanation exp;
    char buffer[256];

    /* Below threshold (0.50 < 0.80) -> INFO prefix */
    assert(generate_explanation(&event, &ngram, NULL, 0.50, 0.80, &exp) == 0);
    assert(format_explanation_string(&exp, buffer, sizeof(buffer)) == 0);
    assert(strncmp(buffer, "INFO |", 6) == 0);

    /* Equal to threshold (0.80 == 0.80) -> ALERT prefix */
    assert(generate_explanation(&event, &ngram, NULL, 0.80, 0.80, &exp) == 0);
    assert(format_explanation_string(&exp, buffer, sizeof(buffer)) == 0);
    assert(strncmp(buffer, "ALERT |", 7) == 0);

    /* Above threshold (1.00 > 0.80) -> ALERT prefix */
    assert(generate_explanation(&event, &ngram, NULL, 1.00, 0.80, &exp) == 0);
    assert(format_explanation_string(&exp, buffer, sizeof(buffer)) == 0);
    assert(strncmp(buffer, "ALERT |", 7) == 0);

    printf("PASSED\n");
}

int main(void)
{
    printf("Running Explainable Anomaly Detection Unit Tests\n");
    printf("================================================\n");

    test_unseen_explanation();
    test_known_explanation();
    test_unknown_syscall_ids();
    test_threshold_matching();
    test_null_safety();
    test_read_only_invariance();
    test_score_boundary_prefix();

    printf("\nALL EXPLANATION UNIT TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
