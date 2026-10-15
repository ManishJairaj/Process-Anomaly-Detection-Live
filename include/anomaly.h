#ifndef ANOMALY_H
#define ANOMALY_H

#include "model.h"

/*
 * SCORING CONTEXT CLARIFICATION:
 *
 * 1. Live Event Score (per-n-gram instantaneous evaluation):
 *    - Unseen 3-gram score  = 1.0 (triggers suspicious event alert if >= ANOMALY_THRESHOLD)
 *    - Seen 3-gram score    = 1.0 / (1.0 + count) <= 0.50 (normal)
 *    - Alert threshold      = ANOMALY_THRESHOLD (0.80)
 *
 * 2. Offline ADFA-LD Trace Score (batch trace ratio evaluation):
 *    - Trace Score          = (unseen 3-grams in trace) / (total 3-grams in trace)
 *    - Calibrated threshold = 0.2500 (validation FPR <= 4.89%)
 */

#define ANOMALY_THRESHOLD 0.80

double anomaly_score(const NormalModel *model,
                     const NGram *ngram);

int anomaly_is_suspicious(double score);

#endif