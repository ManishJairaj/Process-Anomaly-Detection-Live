CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LIBS = -lbpf -lelf -lz

COMMON_SRC = src/event.c src/ngram.c src/window.c src/model.c src/anomaly.c src/explanation.c

TARGETS = syscall-detector ebpf/syscall-detector-live ebpf/syscall-trainer

BENCH_TARGETS = tools/adfa_benchmark tools/adfa_benchmark4 tools/adfa_benchmark4_sweep tools/adfa_model_eval tools/test_model_serialization tools/test_trainer_detector_compat tools/test_explanation tools/test_explanation_integration tools/test_pid_filtering_and_logging tools/train_from_csv tools/eval_baseline_model tools/test_train_label_filtering tools/gen_model_provenance tools/test_eval_independent tools/model_compare tools/gt_evaluate tools/gt_model_compare tools/test_gt_evaluation

all: $(TARGETS)

benchmarks: $(BENCH_TARGETS)

syscall-detector: src/main.c $(COMMON_SRC)
	$(CC) $(CFLAGS) src/main.c $(COMMON_SRC) -o $@

ebpf/syscall-detector-live: ebpf/syscall_collector.c $(COMMON_SRC)
	$(CC) $(CFLAGS) ebpf/syscall_collector.c $(COMMON_SRC) $(LIBS) -o $@

ebpf/syscall-trainer: ebpf/syscall_trainer.c $(COMMON_SRC)
	$(CC) $(CFLAGS) ebpf/syscall_trainer.c $(COMMON_SRC) $(LIBS) -o $@

tools/adfa_benchmark: tools/adfa_benchmark.c $(COMMON_SRC)
	$(CC) $(CFLAGS) -DMAX_MODEL_NGRAMS=20000 $< src/event.c src/ngram.c src/model.c -o $@ -lm

tools/adfa_benchmark4: tools/adfa_benchmark4.c src/event.c
	$(CC) $(CFLAGS) $< src/event.c -o $@ -lm

tools/adfa_benchmark4_sweep: tools/adfa_benchmark4_sweep.c src/event.c
	$(CC) $(CFLAGS) $< src/event.c -o $@ -lm

tools/adfa_model_eval: tools/adfa_model_eval.c src/event.c
	$(CC) $(CFLAGS) $< src/event.c -o $@ -lm

tools/test_model_serialization: tools/test_model_serialization.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_trainer_detector_compat: tools/test_trainer_detector_compat.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_explanation: tools/test_explanation.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_explanation_integration: tools/test_explanation_integration.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_pid_filtering_and_logging: tools/test_pid_filtering_and_logging.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/train_from_csv: tools/train_from_csv.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/eval_baseline_model: tools/eval_baseline_model.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_train_label_filtering: tools/test_train_label_filtering.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/gen_model_provenance: tools/gen_model_provenance.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_eval_independent: tools/test_eval_independent.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/model_compare: tools/model_compare.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/gt_evaluate: tools/gt_evaluate.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/gt_model_compare: tools/gt_model_compare.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

tools/test_gt_evaluation: tools/test_gt_evaluation.c $(COMMON_SRC)
	$(CC) $(CFLAGS) $< $(COMMON_SRC) -o $@ -lm

test: benchmarks
	./tools/test_model_serialization
	./tools/test_trainer_detector_compat
	./tools/test_explanation
	./tools/test_explanation_integration
	./tools/test_pid_filtering_and_logging
	./tools/test_train_label_filtering
	./tools/test_eval_independent
	./tools/test_gt_evaluation
	python3 tools/test_dashboard.py
	python3 tools/test_stage24_launcher.py
	python3 tools/test_stage20_alerts.py
	python3 tools/test_stage21_processes.py
	python3 tools/test_stage22_severity.py
	python3 tools/test_stage25_integration.py

run:
	./run.sh

check:
	./run.sh --check

dashboard:
	./run.sh --dashboard-only

clean:
	rm -f $(TARGETS) $(BENCH_TARGETS)