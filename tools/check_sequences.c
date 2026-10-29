#include <stdio.h>
#include "model.h"
#include "ngram.h"

static void check_sequence(const NormalModel *model, int a, int b, int c)
{
    NGram target = {0};

    target.values[0] = a;
    target.values[1] = b;
    target.values[2] = c;

    for (size_t i = 0; i < model->size; i++)
    {
        if (ngram_equal(&model->entries[i].ngram, &target))
        {
            printf("%d -> %d -> %d : SEEN, count=%lu, probability=%.6f\n",
                   a, b, c,
                   model->entries[i].count,
                   model->entries[i].probability);
            return;
        }
    }

    printf("%d -> %d -> %d : UNSEEN\n", a, b, c);
}

int main(int argc, char **argv)
{
    NormalModel model;
    normal_model_init(&model);

    const char *path = argc > 1 ? argv[1] : "normal_model.dat";

    if (normal_model_load(&model, path) != 0)
    {
        fprintf(stderr, "Failed to load model: %s\n", path);
        return 1;
    }

    check_sequence(&model, 271, 13, 0);
    check_sequence(&model, 13, 271, 13);
    check_sequence(&model, 271, 13, 13);
    check_sequence(&model, 14, 13, 0);
    check_sequence(&model, 1, 13, 0);
    check_sequence(&model, 0, 13, 13);
    check_sequence(&model, 0, 13, 0);
    check_sequence(&model, 271, 13, 271);
    check_sequence(&model, 13, 13, 271);
    check_sequence(&model, 14, 13, 271);

    return 0;
}
