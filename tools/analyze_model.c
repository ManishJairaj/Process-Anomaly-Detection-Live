#include <stdio.h>
#include <stdlib.h>

#include "model.h"
#include "ngram.h"

int main(int argc, char **argv)
{
    const char *model_path = argc > 1 ? argv[1] : "normal_model.dat";

    NormalModel model;
    normal_model_init(&model);

    if (normal_model_load(&model, model_path) != 0)
    {
        fprintf(stderr, "Failed to load model: %s\n", model_path);
        return 1;
    }

    printf("Normal Model Analysis\n");
    printf("=====================\n");
    printf("Unique 3-grams: %zu\n", model.size);
    printf("Total training 3-grams: %lu\n\n", model.total_ngrams);

    printf("Most frequent learned 3-grams:\n");

    for (size_t printed = 0; printed < 10 && printed < model.size; printed++)
    {
        size_t best = model.size;

        for (size_t i = 0; i < model.size; i++)
        {
            if (model.entries[i].count == 0)
                continue;

            int already_printed = 0;

            for (size_t j = 0; j < printed; j++)
            {
                (void)j;
            }

            if (best == model.size ||
                model.entries[i].count > model.entries[best].count)
                best = i;
        }

        if (best == model.size)
            break;

        printf("%d -> %d -> %d | count=%lu | probability=%.6f\n",
               model.entries[best].ngram.values[0],
               model.entries[best].ngram.values[1],
               model.entries[best].ngram.values[2],
               model.entries[best].count,
               model.entries[best].probability);

        model.entries[best].count = 0;
    }

    return 0;
}

