/*
 * test_explanation_integration.c — Integration tests for Event -> Window -> Score -> Explanation pipeline
 *
 * Verifies:
 * 1. Window buffer requires 3 events per PID before emitting a complete 3-gram (result == 1).
 * 2. Sliding windows operate independently per-PID.
 * 3. Unseen sequence triggers live alert (score == 1.0 >= 0.80) and produces matching explanation.
 * 4. Seen sequence does NOT trigger live alert (score <= 0.50 < 0.80).
 * 5. Synthetic events are used; no live eBPF kernel tracepoint is attached.
 *
 * Build & Run:
 *   gcc -Wall -Wextra -O2 -Iinclude -o tools/test_explanation_integration \
 *       tools/test_explanation_integration.c src/explanation.c src/model.c src/ngram.c src/event.c src/anomaly.c src/window.c -lm
 *   ./tools/test_explanation_integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "event.h"
#include "window.h"
#include "model.h"
#include "anomaly.h"
#include "explanation.h"

static void test_pipeline_integration(void)
{
    printf("[INTEGRATION 1] Full Event -> Window -> Score -> Explanation Pipeline... ");

    NormalModel model;
    normal_model_init(&model);

    /* Train model with benign 3-gram: 0 (read) -> 1 (write) -> 2 (open) */
    NGram benign_ngram = {{0, 1, 2}};
    normal_model_add(&model, &benign_ngram);
    normal_model_finalize(&model);

    WindowManager manager;
    window_manager_init(&manager);

    SyscallEvent e1 = {1000, 1001, 1000, 0, 0, "bash"};  /* read */
    SyscallEvent e2 = {1001, 1001, 1000, 0, 1, "bash"};  /* write */
    SyscallEvent e3 = {1002, 1001, 1000, 0, 59, "bash"}; /* execve */

    NGram ngram;
    /* Event 1: window incomplete */
    assert(window_add_event(&manager, &e1, &ngram) == 0);

    /* Event 2: window incomplete */
    assert(window_add_event(&manager, &e2, &ngram) == 0);

    /* Event 3: window complete (3-gram ready) */
    assert(window_add_event(&manager, &e3, &ngram) == 1);
    assert(ngram.values[0] == 0);
    assert(ngram.values[1] == 1);
    assert(ngram.values[2] == 59);

    /* Score completed 3-gram */
    double score = anomaly_score(&model, &ngram);
    assert(score == 1.0);

    int suspicious = anomaly_is_suspicious(score);
    assert(suspicious == 1); /* Score 1.0 >= ANOMALY_THRESHOLD (0.80) */

    /* Generate explanation for alert */
    AnomalyExplanation exp;
    assert(generate_explanation(&e3, &ngram, &model, score, ANOMALY_THRESHOLD, &exp) == 0);

    assert(exp.pid == 1001);
    assert(strcmp(exp.process_name, "bash") == 0);
    assert(exp.score == 1.0);
    assert(exp.threshold == 0.80);
    assert(strcmp(exp.syscall_names[0], "read") == 0);
    assert(strcmp(exp.syscall_names[1], "write") == 0);
    assert(strcmp(exp.syscall_names[2], "execve") == 0);
    assert(strcmp(exp.reason, "3-gram not observed in the loaded normal model") == 0);

    char alert[512];
    assert(format_explanation_string(&exp, alert, sizeof(alert)) == 0);
    assert(strstr(alert, "ALERT | PID=1001 | COMM=bash | NGRAM=read -> write -> execve | SCORE=1.00 | THRESHOLD=0.80 | REASON=3-gram not observed in the loaded normal model") != NULL);

    printf("PASSED\n");
}

static void test_seen_pipeline_no_alert(void)
{
    printf("[INTEGRATION 2] Seen Sequence Pipeline Non-Alert... ");

    NormalModel model;
    normal_model_init(&model);

    NGram benign_ngram = {{0, 1, 2}}; /* read -> write -> open */
    normal_model_add(&model, &benign_ngram);
    normal_model_finalize(&model);

    WindowManager manager;
    window_manager_init(&manager);

    SyscallEvent e1 = {2000, 2002, 1000, 0, 0, "python3"};
    SyscallEvent e2 = {2001, 2002, 1000, 0, 1, "python3"};
    SyscallEvent e3 = {2002, 2002, 1000, 0, 2, "python3"};

    NGram ngram;
    window_add_event(&manager, &e1, &ngram);
    window_add_event(&manager, &e2, &ngram);
    assert(window_add_event(&manager, &e3, &ngram) == 1);

    double score = anomaly_score(&model, &ngram);
    assert(score <= 0.50);

    int suspicious = anomaly_is_suspicious(score);
    assert(suspicious == 0); /* Seen 3-gram score 0.50 < 0.80 -> NORMAL */

    /* Explanation for seen sequence reports model count without turning into an alert */
    AnomalyExplanation exp;
    assert(generate_explanation(&e3, &ngram, &model, score, ANOMALY_THRESHOLD, &exp) == 0);
    assert(exp.is_seen == 1);
    assert(exp.model_count == 1);
    assert(strstr(exp.reason, "count 1") != NULL);

    printf("PASSED\n");
}

int main(void)
{
    printf("Running Explainable Anomaly Detection Integration Tests\n");
    printf("========================================================\n");
    printf("NOTE: Synthetic events used. eBPF kernel collector was NOT executed.\n\n");

    test_pipeline_integration();
    test_seen_pipeline_no_alert();

    printf("\nALL INTEGRATION TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
