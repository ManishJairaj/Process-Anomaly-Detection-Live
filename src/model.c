#include <stdio.h>
#include "model.h"

void normal_model_init(NormalModel *model)
{
    if (model == NULL)
        return;

    model->size = 0;
    model->total_ngrams = 0;
}

static int find_ngram(const NormalModel *model, const NGram *ngram)
{
    for (size_t i = 0; i < model->size; i++)
    {
        if (ngram_equal(&model->entries[i].ngram, ngram))
            return (int)i;
    }

    return -1;
}

int normal_model_add(NormalModel *model, const NGram *ngram)
{
    int index;

    if (model == NULL || ngram == NULL)
        return -1;

    index = find_ngram(model, ngram);

    if (index >= 0)
    {
        model->entries[index].count++;
        model->total_ngrams++;
        return 0;
    }

    if (model->size >= MAX_MODEL_NGRAMS)
        return -1;

    model->entries[model->size].ngram = *ngram;
    model->entries[model->size].count = 1;
    model->entries[model->size].probability = 0.0;

    model->size++;
    model->total_ngrams++;

    return 0;
}

void normal_model_finalize(NormalModel *model)
{
    if (model == NULL || model->total_ngrams == 0)
        return;

    for (size_t i = 0; i < model->size; i++)
    {
        model->entries[i].probability =
            (double)model->entries[i].count /
            (double)model->total_ngrams;
    }
}

void normal_model_print(const NormalModel *model)
{
    if (model == NULL)
        return;

    for (size_t i = 0; i < model->size; i++)
    {
        printf("%d -> %d -> %d : count=%lu probability=%.4f\n",
               model->entries[i].ngram.values[0],
               model->entries[i].ngram.values[1],
               model->entries[i].ngram.values[2],
               model->entries[i].count,
               model->entries[i].probability);
    }
}

int normal_model_save(const NormalModel *model, const char *filename)
{
    FILE *file;

    if (model == NULL || filename == NULL)
        return -1;

    file = fopen(filename, "wb");

    if (file == NULL)
        return -1;

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = (uint32_t)NGRAM_SIZE;
    header.entry_count = (uint32_t)model->size;
    header.total_ngrams = (uint64_t)model->total_ngrams;

    if (fwrite(&header, sizeof(ModelHeader), 1, file) != 1)
    {
        fclose(file);
        return -1;
    }

    if (model->size > 0)
    {
        if (fwrite(model->entries, sizeof(ModelEntry), model->size, file) != model->size)
        {
            fclose(file);
            return -1;
        }
    }

    fclose(file);

    return 0;
}

int normal_model_load(NormalModel *model, const char *filename)
{
    FILE *file;

    if (model == NULL || filename == NULL)
        return -1;

    /* Always leave destination model in a clean, safe state on entry/failure */
    normal_model_init(model);

    file = fopen(filename, "rb");

    if (file == NULL)
        return -1;

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return -1;
    }
    long file_size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return -1;
    }

    /* Support legacy unheadered raw NormalModel dump format (current capacity) */
    if (file_size == (long)sizeof(NormalModel))
    {
        if (fread(model, sizeof(NormalModel), 1, file) != 1)
        {
            normal_model_init(model);
            fclose(file);
            return -1;
        }
        fclose(file);

        if (model->size > MAX_MODEL_NGRAMS)
        {
            fprintf(stderr, "Error: Legacy model size (%zu) exceeds MAX_MODEL_NGRAMS (%d)\n",
                    model->size, MAX_MODEL_NGRAMS);
            normal_model_init(model);
            return -1;
        }
        return 0;
    }

    /* Support legacy 10,000 capacity unheadered raw NormalModel dump format (320,016 bytes) */
    long legacy_10k_size = (long)(sizeof(size_t) + sizeof(unsigned long) + 10000 * sizeof(ModelEntry));
    if (file_size == legacy_10k_size)
    {
        size_t legacy_size = 0;
        unsigned long legacy_total = 0;
        if (fseek(file, 10000 * sizeof(ModelEntry), SEEK_SET) != 0 ||
            fread(&legacy_size, sizeof(size_t), 1, file) != 1 ||
            fread(&legacy_total, sizeof(unsigned long), 1, file) != 1)
        {
            normal_model_init(model);
            fclose(file);
            return -1;
        }

        if (legacy_size > 10000 || legacy_size > (size_t)MAX_MODEL_NGRAMS)
        {
            normal_model_init(model);
            fclose(file);
            return -1;
        }

        if (fseek(file, 0, SEEK_SET) != 0)
        {
            normal_model_init(model);
            fclose(file);
            return -1;
        }

        if (legacy_size > 0)
        {
            if (fread(model->entries, sizeof(ModelEntry), legacy_size, file) != legacy_size)
            {
                normal_model_init(model);
                fclose(file);
                return -1;
            }
        }

        model->size = legacy_size;
        model->total_ngrams = legacy_total;
        fclose(file);
        return 0;
    }

    ModelHeader header;
    if (fread(&header, sizeof(ModelHeader), 1, file) != 1)
    {
        fclose(file);
        return -1;
    }

    if (header.magic != MODEL_MAGIC)
    {
        fprintf(stderr, "Error: Invalid model magic 0x%08X (expected 0x%08X)\n",
                header.magic, MODEL_MAGIC);
        fclose(file);
        return -1;
    }

    if (header.version != MODEL_VERSION)
    {
        fprintf(stderr, "Error: Unsupported model version %u (expected %u)\n",
                header.version, MODEL_VERSION);
        fclose(file);
        return -1;
    }

    if (header.ngram_size != (uint32_t)NGRAM_SIZE)
    {
        fprintf(stderr, "Error: Incompatible model n-gram size %u (expected %d)\n",
                header.ngram_size, NGRAM_SIZE);
        fclose(file);
        return -1;
    }

    if (header.entry_count > (uint32_t)MAX_MODEL_NGRAMS)
    {
        fprintf(stderr, "Error: Model entry count %u exceeds maximum capacity %d\n",
                header.entry_count, MAX_MODEL_NGRAMS);
        fclose(file);
        return -1;
    }

    long expected_size = (long)(sizeof(ModelHeader) + (size_t)header.entry_count * sizeof(ModelEntry));
    if (file_size < expected_size)
    {
        fprintf(stderr, "Error: Model file truncated (size %ld bytes, expected %ld bytes)\n",
                file_size, expected_size);
        fclose(file);
        return -1;
    }

    if (header.entry_count > 0)
    {
        if (fread(model->entries, sizeof(ModelEntry), header.entry_count, file) != header.entry_count)
        {
            normal_model_init(model);
            fclose(file);
            return -1;
        }

        /* Validate entry count, syscall ID range, and uniqueness invariants */
        for (uint32_t i = 0; i < header.entry_count; i++)
        {
            if (model->entries[i].count == 0)
            {
                fprintf(stderr, "Error: Model entry %u has invalid zero count\n", i);
                normal_model_init(model);
                fclose(file);
                return -1;
            }

            for (int k = 0; k < NGRAM_SIZE; k++)
            {
                if (model->entries[i].ngram.values[k] < 0)
                {
                    fprintf(stderr, "Error: Model entry %u has negative syscall ID %d\n",
                            i, model->entries[i].ngram.values[k]);
                    normal_model_init(model);
                    fclose(file);
                    return -1;
                }
            }

            for (uint32_t j = 0; j < i; j++)
            {
                if (ngram_equal(&model->entries[i].ngram, &model->entries[j].ngram))
                {
                    fprintf(stderr, "Error: Duplicate model entry detected at index %u\n", i);
                    normal_model_init(model);
                    fclose(file);
                    return -1;
                }
            }
        }
    }

    model->size = (size_t)header.entry_count;
    model->total_ngrams = (unsigned long)header.total_ngrams;

    fclose(file);

    return 0;
}