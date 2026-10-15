#include <stdio.h>
#include "ngram.h"

void ngram_table_init(NGramTable *table)
{
    table->size = 0;
}

int ngram_equal(const NGram *a, const NGram *b)
{
    for (size_t i = 0; i < NGRAM_SIZE; i++)
    {
        if (a->values[i] != b->values[i])
            return 0;
    }

    return 1;
}

int ngram_table_add(NGramTable *table, const NGram *ngram)
{
    for (size_t i = 0; i < table->size; i++)
    {
        if (ngram_equal(&table->entries[i].ngram, ngram))
        {
            table->entries[i].count++;
            return 0;
        }
    }

    if (table->size >= MAX_NGRAMS)
        return -1;

    table->entries[table->size].ngram = *ngram;
    table->entries[table->size].count = 1;
    table->size++;

    return 0;
}

void ngram_table_print(const NGramTable *table)
{
    for (size_t i = 0; i < table->size; i++)
    {
        printf("%d -> %d -> %d : %lu\n",
               table->entries[i].ngram.values[0],
               table->entries[i].ngram.values[1],
               table->entries[i].ngram.values[2],
               table->entries[i].count);
    }
}
