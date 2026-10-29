#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ngram.h"
#include "model.h"

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options] <input_dataset.csv> <output_model.dat>\n", prog_name);
    printf("Options:\n");
    printf("  -f, --force        Overwrite output model file if it already exists\n");
    printf("  --normal-only      Train only on rows where predicted_label == NORMAL\n");
    printf("                     (rows with label SUSPICIOUS or missing/invalid\n");
    printf("                      labels are excluded and counted separately)\n");
    printf("  -h, --help         Show this help message\n");
}

int main(int argc, char **argv)
{
    int force_overwrite = 0;
    int normal_only     = 0;  /* --normal-only flag */
    const char *csv_path  = NULL;
    const char *model_path = NULL;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--force") == 0)
        {
            force_overwrite = 1;
        }
        else if (strcmp(argv[i], "--normal-only") == 0)
        {
            normal_only = 1;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
        else if (csv_path == NULL)
        {
            csv_path = argv[i];
        }
        else if (model_path == NULL)
        {
            model_path = argv[i];
        }
        else
        {
            fprintf(stderr, "Error: Unknown argument %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (csv_path == NULL || model_path == NULL)
    {
        fprintf(stderr, "Error: Missing input CSV or output model file path\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Safety Check 1: Do NOT allow overwriting protected core model files */
    if (strcmp(model_path, "normal_model.dat") == 0 ||
        strcmp(model_path, "../normal_model.dat") == 0)
    {
        fprintf(stderr, "Error: Safety violation. Cannot overwrite core normal_model.dat!\n");
        return 1;
    }
    if (strcmp(model_path, "baseline_model.dat") == 0 ||
        strcmp(model_path, "../baseline_model.dat") == 0)
    {
        fprintf(stderr, "Error: Safety violation. Cannot overwrite core baseline_model.dat!\n");
        return 1;
    }

    /* Safety Check 2: If destination model file exists, require -f / --force */
    if (access(model_path, F_OK) == 0 && !force_overwrite)
    {
        fprintf(stderr, "Error: Output file '%s' already exists. Pass -f or --force to overwrite.\n", model_path);
        return 1;
    }

    FILE *f = fopen(csv_path, "r");
    if (!f)
    {
        perror("Failed to open input CSV");
        return 1;
    }

    NormalModel model;
    normal_model_init(&model);

    char line[1024];
    unsigned long rows_processed = 0;  /* rows accepted and trained on */
    unsigned long rows_excluded  = 0;  /* rows skipped by --normal-only filter */
    unsigned long ngrams_added   = 0;
    unsigned long malformed_rows = 0;

    /* ---------------------------------------------------------------
     * Header parsing: detect column positions by name so the tool
     * remains robust against future column reordering.
     * Expected header (from live collector):
     *   monotonic_timestamp_ns, pid, process_name,
     *   syscall_1, syscall_2, syscall_3,
     *   anomaly_score, predicted_label
     * --------------------------------------------------------------- */
    if (!fgets(line, sizeof(line), f))
    {
        fprintf(stderr, "Error: Empty CSV file: %s\n", csv_path);
        fclose(f);
        return 1;
    }

    /* Parse header to discover column indices (1-based) */
    int col_s1    = -1, col_s2 = -1, col_s3 = -1, col_label = -1;
    {
        char hdr_buf[1024];
        strncpy(hdr_buf, line, sizeof(hdr_buf) - 1);
        hdr_buf[sizeof(hdr_buf) - 1] = '\0';
        /* Strip trailing newline for cleaner matching */
        char *nl = strchr(hdr_buf, '\n');
        if (nl) *nl = '\0';

        char *tok, *rest_h = hdr_buf;
        int cidx = 0;
        while ((tok = strtok_r(rest_h, ",", &rest_h)) != NULL)
        {
            cidx++;
            /* Trim surrounding whitespace/quotes from each header token */
            while (*tok == ' ' || *tok == '"') tok++;
            size_t tlen = strlen(tok);
            while (tlen > 0 && (tok[tlen-1] == ' ' || tok[tlen-1] == '"' ||
                                tok[tlen-1] == '\r'))
                tok[--tlen] = '\0';

            if (strcmp(tok, "syscall_1") == 0)        col_s1    = cidx;
            else if (strcmp(tok, "syscall_2") == 0)   col_s2    = cidx;
            else if (strcmp(tok, "syscall_3") == 0)   col_s3    = cidx;
            else if (strcmp(tok, "predicted_label") == 0) col_label = cidx;
        }
    }

    /* Fall back to hard-coded columns if header is non-standard */
    if (col_s1 < 0) col_s1 = 4;
    if (col_s2 < 0) col_s2 = 5;
    if (col_s3 < 0) col_s3 = 6;

    if (normal_only && col_label < 0)
    {
        fprintf(stderr,
                "Warning: 'predicted_label' column not found in CSV header.\n"
                "         --normal-only filtering requires this column.\n"
                "         All rows will be excluded to avoid silent contamination.\n");
        /* Set col_label to a sentinel that will never match so every row
         * ends up in 'excluded'. This is deliberately conservative. */
        col_label = -2;  /* sentinel: header absent, filter everything */
    }

    while (fgets(line, sizeof(line), f))
    {
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
            continue; /* Skip duplicate embedded headers */

        char line_buf[1024];
        strncpy(line_buf, line, sizeof(line_buf) - 1);
        line_buf[sizeof(line_buf) - 1] = '\0';

        char *token;
        char *rest = line_buf;
        int col = 0;
        int s1 = -1, s2 = -1, s3 = -1;
        char label_buf[32] = "";
        int label_col_found = 0;

        while ((token = strtok_r(rest, ",", &rest)) != NULL)
        {
            col++;
            if (col == col_s1) s1 = atoi(token);
            else if (col == col_s2) s2 = atoi(token);
            else if (col == col_s3) s3 = atoi(token);
            else if (col_label > 0 && col == col_label)
            {
                /* Trim whitespace, newlines, and quotes */
                strncpy(label_buf, token, sizeof(label_buf) - 1);
                label_buf[sizeof(label_buf) - 1] = '\0';
                char *lp = label_buf;
                while (*lp == ' ' || *lp == '"') lp++;
                size_t llen = strlen(lp);
                while (llen > 0 && (lp[llen-1] == '\n' || lp[llen-1] == '\r' ||
                                    lp[llen-1] == ' '  || lp[llen-1] == '"'))
                    lp[--llen] = '\0';
                strncpy(label_buf, lp, sizeof(label_buf) - 1);
                label_buf[sizeof(label_buf) - 1] = '\0';
                label_col_found = 1;
            }
        }

        /* --normal-only: skip rows that are not labelled NORMAL */
        if (normal_only)
        {
            if (col_label == -2)
            {
                /* Header-absent sentinel: exclude all rows */
                rows_excluded++;
                continue;
            }
            if (!label_col_found || strcmp(label_buf, "NORMAL") != 0)
            {
                rows_excluded++;
                continue;
            }
        }

        if (s1 >= 0 && s2 >= 0 && s3 >= 0)
        {
            NGram ngram = {{s1, s2, s3}};
            if (normal_model_add(&model, &ngram) == 0)
                ngrams_added++;

            rows_processed++;
        }
        else
        {
            malformed_rows++;
        }
    }

    fclose(f);

    if (ngrams_added == 0)
    {
        fprintf(stderr, "Error: No valid 3-grams extracted from CSV (%s)\n", csv_path);
        return 1;
    }

    normal_model_finalize(&model);

    if (normal_model_save(&model, model_path) != 0)
    {
        fprintf(stderr, "Error: Failed to save trained model to %s\n", model_path);
        return 1;
    }

    printf("CSV Model Training Complete\n");
    printf("===========================\n");
    printf("Input CSV         : %s\n", csv_path);
    printf("Filter Mode       : %s\n", normal_only ? "--normal-only (NORMAL rows only)" : "all rows (default)");
    printf("Rows Accepted     : %lu\n", rows_processed);
    printf("Rows Excluded     : %lu\n", rows_excluded);
    printf("Malformed Rows    : %lu\n", malformed_rows);
    printf("N-grams Added     : %lu\n", ngrams_added);
    printf("Unique 3-grams    : %zu\n", model.size);
    printf("Output Model File : %s\n", model_path);

    return 0;
}
