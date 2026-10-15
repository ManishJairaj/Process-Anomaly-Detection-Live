#ifndef MODEL_H
#define MODEL_H

#include <stddef.h>
#include "ngram.h"

#ifndef MAX_MODEL_NGRAMS
#define MAX_MODEL_NGRAMS 30000
#endif

#define MODEL_MAGIC 0x5041444Du  /* "PADM" in ASCII */
#define MODEL_VERSION 1u

typedef struct {
    uint32_t magic;         /* MODEL_MAGIC */
    uint32_t version;       /* MODEL_VERSION */
    uint32_t ngram_size;    /* NGRAM_SIZE = 3 */
    uint32_t entry_count;   /* model->size */
    uint64_t total_ngrams;  /* model->total_ngrams */
} ModelHeader;

typedef struct {
    NGram ngram;
    unsigned long count;
    double probability;
} ModelEntry;

typedef struct {
    ModelEntry entries[MAX_MODEL_NGRAMS];
    size_t size;
    unsigned long total_ngrams;
} NormalModel;

void normal_model_init(NormalModel *model);

int normal_model_add(NormalModel *model, const NGram *ngram);

void normal_model_finalize(NormalModel *model);

void normal_model_print(const NormalModel *model);

int normal_model_save(const NormalModel *model, const char *filename);

int normal_model_load(NormalModel *model, const char *filename);

#endif