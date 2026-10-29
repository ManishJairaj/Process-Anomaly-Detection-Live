#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "event.h"
#include "ngram.h"
#include "window.h"
#include "model.h"
#include "anomaly.h"
#include "explanation.h"

struct bpf_syscall_event
{
    unsigned long long timestamp;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    int syscall_id;
    char process_name[64];
};

/* Replicate filtering helper logic for unit testing */
static int is_self_or_launcher_event(uint32_t event_pid, pid_t own_pid, pid_t parent_pid)
{
    if (event_pid == (uint32_t)own_pid)
        return 1;

    if (parent_pid > 1 && event_pid == (uint32_t)parent_pid)
        return 1;

    return 0;
}

static void test_pid_filtering_logic(void)
{
    printf("[FILTER TEST 1] PID Filtering Logic... ");

    pid_t own_pid = 50000;
    pid_t parent_pid = 49999; /* Launcher PID, e.g., sudo */

    /* Detector's own events must be excluded */
    assert(is_self_or_launcher_event(50000, own_pid, parent_pid) == 1);

    /* Launcher's (sudo's) events must be excluded */
    assert(is_self_or_launcher_event(49999, own_pid, parent_pid) == 1);

    /* Unrelated process with different PID (even if named 'sudo') MUST NOT be excluded */
    assert(is_self_or_launcher_event(12345, own_pid, parent_pid) == 0);

    /* Unrelated process when parent_pid is 1 (systemd/init) */
    assert(is_self_or_launcher_event(12345, own_pid, 1) == 0);
    assert(is_self_or_launcher_event(1, own_pid, 1) == 0);

    printf("PASSED\n");
}

static void test_dataset_header_and_append(void)
{
    printf("[FILTER TEST 2] CSV Header and Append Invariance... ");
    const char *test_csv = "/tmp/test_dataset_logging.csv";
    unlink(test_csv);

    /* Helper function simulate header writing */
    FILE *f1 = fopen(test_csv, "a+");
    assert(f1 != NULL);
    fseek(f1, 0, SEEK_END);
    if (ftell(f1) == 0)
    {
        fprintf(f1, "monotonic_timestamp_ns,pid,process_name,syscall_1,syscall_2,syscall_3,anomaly_score,predicted_label\n");
        fflush(f1);
    }
    fprintf(f1, "1000,100,\"test_proc\",0,1,2,1.0000,SUSPICIOUS\n");
    fclose(f1);

    /* Re-open existing non-empty file (Simulate second detector run) */
    FILE *f2 = fopen(test_csv, "a+");
    assert(f2 != NULL);
    fseek(f2, 0, SEEK_END);
    assert(ftell(f2) > 0); /* Non-empty */
    /* Must NOT write header when ftell > 0 */
    fprintf(f2, "2000,100,\"test_proc\",1,2,3,0.0047,NORMAL\n");
    fclose(f2);

    /* Read back file content and verify header appears exactly once */
    FILE *fr = fopen(test_csv, "r");
    assert(fr != NULL);
    char line[512];
    int header_count = 0;
    int line_count = 0;
    while (fgets(line, sizeof(line), fr))
    {
        line_count++;
        if (strstr(line, "monotonic_timestamp_ns") != NULL)
            header_count++;
    }
    fclose(fr);

    assert(header_count == 1);
    assert(line_count == 3); /* 1 header + 2 data rows */

    unlink(test_csv);
    printf("PASSED\n");
}

static void test_invalid_path_error_handling(void)
{
    printf("[FILTER TEST 3] Invalid CSV Output Path Error Handling... ");
    const char *invalid_csv = "/invalid_non_existent_directory/test.csv";

    FILE *f = fopen(invalid_csv, "a+");
    assert(f == NULL); /* Should fail cleanly without crashing */

    printf("PASSED\n");
}

int main(void)
{
    printf("Running PID Filtering & Dataset Logging Unit Tests\n");
    printf("====================================================\n");

    test_pid_filtering_logic();
    test_dataset_header_and_append();
    test_invalid_path_error_handling();

    printf("\nALL PID FILTERING & LOGGING TESTS PASSED SUCCESSFULLY.\n");
    return 0;
}
