#ifndef NGRAM_H
#define NGRAM_H

#include <stddef.h>
#include "event.h"

#define NGRAM_SIZE 3
#define MAX_NGRAMS 1000

typedef struct {
    int values[NGRAM_SIZE];
} NGram;

typedef struct {
    NGram ngram;
    unsigned long count;
} NGramEntry;

typedef struct {
    NGramEntry entries[MAX_NGRAMS];
    size_t size;
} NGramTable;

void ngram_table_init(NGramTable *table);

int ngram_equal(const NGram *a, const NGram *b);

int ngram_table_add(NGramTable *table, const NGram *ngram);

void ngram_table_print(const NGramTable *table);



#endif
