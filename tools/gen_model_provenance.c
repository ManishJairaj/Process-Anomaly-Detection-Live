/*
 * gen_model_provenance.c — Model Provenance JSON Generator (Stage 18)
 *
 * Generates a <model>.provenance.json file recording:
 *   - Model filename and SHA-256 hash
 *   - Model format version, unique 3-gram count, total training 3-grams
 *   - Training dataset path and SHA-256 (when supplied via --train-csv)
 *   - Training method / label filter (when supplied via --filter-mode)
 *   - Generation timestamp
 *
 * Fields that are not supplied are recorded as null.
 * The binary model format is NOT modified.
 *
 * Usage:
 *   ./tools/gen_model_provenance --model <model.dat> [options]
 *
 * Options:
 *   --model     <path>     Model .dat file (required)
 *   --train-csv <path>     Path to training dataset CSV (optional)
 *   --filter-mode <str>    Training filter description (optional)
 *                          e.g. "all-rows" or "normal-only"
 *   --force                Overwrite existing provenance file
 *   -h, --help             Show this help
 *
 * Output: <model>.provenance.json (same directory as model)
 *
 * SHA-256 implementation: calls sha256sum(1) via popen() — requires
 * coreutils on the host, which is standard on all major Linux distributions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "model.h"

/* -----------------------------------------------------------------------
 * Compute SHA-256 of a file by invoking sha256sum(1).
 * Writes hex digest (64 chars) into buf[65].
 * Returns 0 on success, -1 on failure.
 * ----------------------------------------------------------------------- */
static int file_sha256(const char *path, char buf[65])
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null", path);

    buf[0] = '\0';

    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return -1;

    char line[256];
    if (fgets(line, sizeof(line), pipe) == NULL)
    {
        pclose(pipe);
        return -1;
    }
    pclose(pipe);

    /* sha256sum output: "<64-hex-chars>  <filename>" */
    if (strlen(line) < 64)
        return -1;

    strncpy(buf, line, 64);
    buf[64] = '\0';

    /* Validate all 64 chars are hex digits */
    for (int i = 0; i < 64; i++)
    {
        char c = buf[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return -1;
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * json_string: write a JSON string value, escaping backslash and quote.
 * ----------------------------------------------------------------------- */
static void json_string(FILE *f, const char *s)
{
    if (s == NULL)
    {
        fprintf(f, "null");
        return;
    }
    fputc('"', f);
    for (; *s; s++)
    {
        if (*s == '"')  fprintf(f, "\\\"");
        else if (*s == '\\') fprintf(f, "\\\\");
        else            fputc(*s, f);
    }
    fputc('"', f);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s --model <model.dat> [options]\n\n", prog);
    printf("Options:\n");
    printf("  --model      <path>   Model .dat file (required)\n");
    printf("  --train-csv  <path>   Training dataset CSV path (optional)\n");
    printf("  --filter-mode <str>   Training filter description (optional)\n");
    printf("                        e.g. \"all-rows\" or \"normal-only\"\n");
    printf("  --force               Overwrite existing provenance file\n");
    printf("  -h, --help            Show this help\n\n");
    printf("Output: <model>.provenance.json\n");
}

int main(int argc, char **argv)
{
    const char *model_path      = NULL;
    const char *train_csv_path  = NULL;
    const char *filter_mode     = NULL;
    int         force_overwrite = 0;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--model") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --model needs a path\n"); return 1; }
            model_path = argv[++i];
        }
        else if (strcmp(argv[i], "--train-csv") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --train-csv needs a path\n"); return 1; }
            train_csv_path = argv[++i];
        }
        else if (strcmp(argv[i], "--filter-mode") == 0)
        {
            if (i + 1 >= argc) { fprintf(stderr, "Error: --filter-mode needs a value\n"); return 1; }
            filter_mode = argv[++i];
        }
        else if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0)
        {
            force_overwrite = 1;
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (model_path == NULL)
    {
        fprintf(stderr, "Error: --model is required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Check model file exists */
    if (access(model_path, F_OK) != 0)
    {
        fprintf(stderr, "Error: Model file not found: %s\n", model_path);
        return 1;
    }

    /* Build output provenance file path: <model_path>.provenance.json */
    char prov_path[1024];
    snprintf(prov_path, sizeof(prov_path), "%s.provenance.json", model_path);

    if (access(prov_path, F_OK) == 0 && !force_overwrite)
    {
        fprintf(stderr, "Error: Provenance file already exists: %s\n", prov_path);
        fprintf(stderr, "       Use --force to overwrite.\n");
        return 1;
    }

    /* Load model to extract metadata */
    NormalModel model;
    if (normal_model_load(&model, model_path) != 0)
    {
        fprintf(stderr, "Error: Failed to load model: %s\n", model_path);
        return 1;
    }

    /* Compute model SHA-256 */
    char model_sha256[65] = "";
    int model_hash_ok = (file_sha256(model_path, model_sha256) == 0);

    /* Compute training CSV SHA-256 if supplied */
    char train_sha256[65] = "";
    int train_hash_ok = 0;
    if (train_csv_path != NULL)
    {
        printf("Computing SHA-256 of training dataset (may take a moment for large files)...\n");
        train_hash_ok = (file_sha256(train_csv_path, train_sha256) == 0);
    }

    /* Stat model file for size */
    struct stat mst;
    long model_bytes = -1;
    if (stat(model_path, &mst) == 0)
        model_bytes = (long)mst.st_size;

    /* Get current UTC timestamp */
    time_t now = time(NULL);
    char ts_buf[64] = "";
    struct tm *utc = gmtime(&now);
    if (utc)
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", utc);

    /* Write JSON provenance file */
    FILE *pf = fopen(prov_path, "w");
    if (!pf)
    {
        perror("Error: Cannot write provenance file");
        return 1;
    }

    fprintf(pf, "{\n");

    fprintf(pf, "  \"schema_version\": 1,\n");
    fprintf(pf, "  \"generated_at\": ");
    json_string(pf, ts_buf[0] ? ts_buf : NULL);
    fprintf(pf, ",\n");

    /* Model identity */
    fprintf(pf, "  \"model_file\": ");
    json_string(pf, model_path);
    fprintf(pf, ",\n");

    fprintf(pf, "  \"model_sha256\": ");
    json_string(pf, model_hash_ok ? model_sha256 : NULL);
    fprintf(pf, ",\n");

    fprintf(pf, "  \"model_file_bytes\": %ld,\n", model_bytes);
    fprintf(pf, "  \"model_format_magic\": \"0x%08X\",\n", MODEL_MAGIC);
    fprintf(pf, "  \"model_format_version\": %u,\n", MODEL_VERSION);
    fprintf(pf, "  \"ngram_size\": %d,\n", NGRAM_SIZE);
    fprintf(pf, "  \"unique_ngrams\": %zu,\n", model.size);
    fprintf(pf, "  \"total_training_ngrams\": %lu,\n", model.total_ngrams);

    /* Training dataset */
    fprintf(pf, "  \"training_dataset_path\": ");
    json_string(pf, train_csv_path);
    fprintf(pf, ",\n");

    fprintf(pf, "  \"training_dataset_sha256\": ");
    json_string(pf, (train_csv_path && train_hash_ok) ? train_sha256 : NULL);
    fprintf(pf, ",\n");

    /* Training method */
    fprintf(pf, "  \"training_method\": ");
    json_string(pf, "syscall-3gram-frequency-count");
    fprintf(pf, ",\n");

    fprintf(pf, "  \"label_filter\": ");
    json_string(pf, filter_mode);
    fprintf(pf, ",\n");

    /* Disclaimer */
    fprintf(pf, "  \"disclaimer\": ");
    json_string(pf, "Training labels are detector-generated predictions, "
                    "not independently verified ground truth. "
                    "Provenance fields marked null were not supplied at generation time.");
    fprintf(pf, "\n");

    fprintf(pf, "}\n");
    fclose(pf);

    printf("Model Provenance Generated\n");
    printf("==========================\n");
    printf("Model File       : %s\n", model_path);
    printf("Model SHA-256    : %s\n", model_hash_ok ? model_sha256 : "(unavailable)");
    printf("Model Size       : %ld bytes\n", model_bytes);
    printf("Format Version   : %u\n", MODEL_VERSION);
    printf("N-gram Size      : %d\n", NGRAM_SIZE);
    printf("Unique 3-grams   : %zu\n", model.size);
    printf("Total 3-grams    : %lu\n", model.total_ngrams);
    printf("Training CSV     : %s\n", train_csv_path ? train_csv_path : "(not supplied)");
    if (train_csv_path)
        printf("Training SHA-256 : %s\n", train_hash_ok ? train_sha256 : "(unavailable)");
    printf("Filter Mode      : %s\n", filter_mode ? filter_mode : "(not supplied)");
    printf("Generated At     : %s\n", ts_buf[0] ? ts_buf : "(unavailable)");
    printf("Provenance File  : %s\n", prov_path);

    return 0;
}
