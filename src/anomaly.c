#include "anomaly.h"

static const ModelEntry *find_model_entry(const NormalModel *model,
                                          const NGram *ngram)
{
    if (model == NULL || ngram == NULL)
        return NULL;

    for (size_t i = 0; i < model->size; i++)
    {
        if (ngram_equal(&model->entries[i].ngram, ngram))
            return &model->entries[i];
    }

    return NULL;
}

double anomaly_score(const NormalModel *model,
                     const NGram *ngram)
{
    const ModelEntry *entry = find_model_entry(model, ngram);

    if (entry == NULL)
        return 1.0;

    return 1.0 / (1.0 + (double)entry->count);
}

int anomaly_is_suspicious(double score)
{
    return score >= ANOMALY_THRESHOLD;
}

