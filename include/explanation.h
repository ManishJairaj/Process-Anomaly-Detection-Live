#ifndef EXPLANATION_H
#define EXPLANATION_H

#include <stddef.h>
#include "event.h"
#include "ngram.h"
#include "model.h"

typedef struct {
    unsigned int pid;
    char process_name[PROCESS_NAME_LEN];
    NGram ngram;
    int is_seen;               /* 1 if found in model, 0 if unseen */
    unsigned long model_count; /* stored count if seen, 0 if unseen */
    double score;              /* computed live event score */
    double threshold;          /* live threshold (ANOMALY_THRESHOLD = 0.80) */
    char syscall_names[NGRAM_SIZE][32]; /* human readable names for values[0..2] */
    char reason[128];          /* concise factual reason */
} AnomalyExplanation;

/*
 * Convert syscall ID to human-readable string for Linux x86_64 architecture.
 * Unknown or negative IDs produce safe "unknown(<id>)" format.
 */
const char *get_syscall_name(int syscall_id, char *buffer, size_t buffer_size);

/*
 * Pure read-only explanation generator.
 * Populates AnomalyExplanation struct without modifying model or scoring state.
 */
int generate_explanation(const SyscallEvent *event,
                         const NGram *ngram,
                         const NormalModel *model,
                         double score,
                         double threshold,
                         AnomalyExplanation *exp);

/*
 * Format structured AnomalyExplanation into a standardized single-line alert string.
 */
int format_explanation_string(const AnomalyExplanation *exp,
                              char *buffer,
                              size_t buffer_size);

/*
 * Output formatted anomaly explanation to stdout.
 * Preserved for backward compatibility with ebpf/syscall_collector.c and main.c.
 */
void explain_anomaly(const SyscallEvent *event,
                     const NGram *ngram,
                     const NormalModel *model,
                     double score);

#endif