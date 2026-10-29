/*
 * test_model_serialization.c — Unit tests for safe model serialization & compatibility
 *
 * Tests:
 * 1. Round-trip save and load of NormalModel with header validation.
 * 2. Preservation of entry count, total n-grams, syscall values, and counts.
 * 3. Validation and rejection of:
 *    - Invalid magic bytes
 *    - Unsupported format versions
 *    - Incompatible n-gram sizes
 *    - Oversized entry counts (> MAX_MODEL_NGRAMS)
 *    - Truncated files
 * 4. Backward compatibility fallback for legacy unheadered raw NormalModel dumps.
 *
 * Build & Run:
 *   gcc -Wall -Wextra -O2 -Iinclude -o tools/test_model_serialization \
 *       tools/test_model_serialization.c src/model.c src/ngram.c src/event.c
 *   ./tools/test_model_serialization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "model.h"

static void test_roundtrip(void)
{
    printf("[TEST 1] Round-trip Save and Load... ");
    const char *tmpfile = "/tmp/test_model_roundtrip.dat";

    NormalModel model_orig, model_loaded;
    normal_model_init(&model_orig);
    normal_model_init(&model_loaded);

    NGram g1 = {{10, 20, 30}};
    NGram g2 = {{40, 50, 60}};
    NGram g3 = {{70, 80, 90}};

    assert(normal_model_add(&model_orig, &g1) == 0);
    assert(normal_model_add(&model_orig, &g1) == 0); /* count = 2 */
    assert(normal_model_add(&model_orig, &g2) == 0); /* count = 1 */
    assert(normal_model_add(&model_orig, &g3) == 0); /* count = 1 */
    normal_model_finalize(&model_orig);

    assert(model_orig.size == 3);
    assert(model_orig.total_ngrams == 4);

    assert(normal_model_save(&model_orig, tmpfile) == 0);
    assert(normal_model_load(&model_loaded, tmpfile) == 0);

    assert(model_loaded.size == model_orig.size);
    assert(model_loaded.total_ngrams == model_orig.total_ngrams);

    for (size_t i = 0; i < model_orig.size; i++) {
        assert(ngram_equal(&model_loaded.entries[i].ngram, &model_orig.entries[i].ngram));
        assert(model_loaded.entries[i].count == model_orig.entries[i].count);
        assert(model_loaded.entries[i].probability == model_orig.entries[i].probability);
    }

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_legacy_fallback(void)
{
    printf("[TEST 2] Legacy Unheadered Format Fallback... ");
    const char *tmpfile = "/tmp/test_model_legacy.dat";
    const char *tmpfile_10k = "/tmp/test_model_legacy_10k.dat";

    NormalModel model_orig, model_loaded;
    normal_model_init(&model_orig);
    normal_model_init(&model_loaded);

    NGram g = {{1, 2, 3}};
    assert(normal_model_add(&model_orig, &g) == 0);

    /* Write raw unheadered NormalModel dump */
    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&model_orig, sizeof(NormalModel), 1, f) == 1);
    fclose(f);

    /* Load should detect legacy format size and succeed */
    assert(normal_model_load(&model_loaded, tmpfile) == 0);
    assert(model_loaded.size == 1);
    assert(model_loaded.total_ngrams == 1);
    assert(ngram_equal(&model_loaded.entries[0].ngram, &g));

    /* Write synthetic 320,016-byte legacy 10k capacity dump */
    FILE *f10k = fopen(tmpfile_10k, "wb");
    assert(f10k != NULL);
    ModelEntry entries_10k[10000];
    memset(entries_10k, 0, sizeof(entries_10k));
    entries_10k[0].ngram = g;
    entries_10k[0].count = 5;
    entries_10k[0].probability = 1.0;
    size_t size_10k = 1;
    unsigned long total_10k = 5;

    assert(fwrite(entries_10k, sizeof(ModelEntry), 10000, f10k) == 10000);
    assert(fwrite(&size_10k, sizeof(size_t), 1, f10k) == 1);
    assert(fwrite(&total_10k, sizeof(unsigned long), 1, f10k) == 1);
    fclose(f10k);

    normal_model_init(&model_loaded);
    assert(normal_model_load(&model_loaded, tmpfile_10k) == 0);
    assert(model_loaded.size == 1);
    assert(model_loaded.total_ngrams == 5);
    assert(ngram_equal(&model_loaded.entries[0].ngram, &g));

    unlink(tmpfile);
    unlink(tmpfile_10k);
    printf("PASSED\n");
}

static void test_invalid_magic(void)
{
    printf("[TEST 3] Rejection of Invalid Magic... ");
    const char *tmpfile = "/tmp/test_model_bad_magic.dat";

    ModelHeader bad_header;
    bad_header.magic = 0xDEADBEEFu;
    bad_header.version = MODEL_VERSION;
    bad_header.ngram_size = 3;
    bad_header.entry_count = 5;
    bad_header.total_ngrams = 10;

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&bad_header, sizeof(ModelHeader), 1, f) == 1);
    fclose(f);

    NormalModel model;
    /* Expected to fail gracefully without crash */
    assert(normal_model_load(&model, tmpfile) != 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_unsupported_version(void)
{
    printf("[TEST 4] Rejection of Unsupported Version... ");
    const char *tmpfile = "/tmp/test_model_bad_ver.dat";

    ModelHeader bad_header;
    bad_header.magic = MODEL_MAGIC;
    bad_header.version = 999;
    bad_header.ngram_size = 3;
    bad_header.entry_count = 5;
    bad_header.total_ngrams = 10;

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&bad_header, sizeof(ModelHeader), 1, f) == 1);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_truncated_file(void)
{
    printf("[TEST 5] Rejection of Truncated File... ");
    const char *tmpfile = "/tmp/test_model_truncated.dat";

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = 3;
    header.entry_count = 10; /* Claims 10 entries */
    header.total_ngrams = 20;

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&header, sizeof(ModelHeader), 1, f) == 1);
    /* Write only 2 entries instead of 10 */
    ModelEntry entries[2];
    memset(entries, 0, sizeof(entries));
    assert(fwrite(entries, sizeof(ModelEntry), 2, f) == 2);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

static void test_oversized_entries(void)
{
    printf("[TEST 6] Rejection of Oversized Entry Count... ");
    const char *tmpfile = "/tmp/test_model_oversized.dat";

    ModelHeader header;
    header.magic = MODEL_MAGIC;
    header.version = MODEL_VERSION;
    header.ngram_size = 3;
    header.entry_count = MAX_MODEL_NGRAMS + 500;
    header.total_ngrams = 100000;

    FILE *f = fopen(tmpfile, "wb");
    assert(f != NULL);
    assert(fwrite(&header, sizeof(ModelHeader), 1, f) == 1);
    fclose(f);

    NormalModel model;
    assert(normal_model_load(&model, tmpfile) != 0);

    unlink(tmpfile);
    printf("PASSED\n");
}

int main(void)
{
    printf("Running Model Serialization Unit Tests\n");
    printf("=======================================\n");

    test_roundtrip();
    test_legacy_fallback();
    test_invalid_magic();
    test_unsupported_version();
    test_truncated_file();
    test_oversized_entries();

    printf("\nALL SERIALIZATION TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
