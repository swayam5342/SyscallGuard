CC       ?= gcc
CFLAGS   ?= -std=c11 -O2 -g -Wall -Wextra -Wpedantic
CPPFLAGS += -Isrc
BUILD    := build

HEADERS := $(wildcard src/*.h)
CORE    := $(BUILD)/costs.o $(BUILD)/bucket.o $(BUILD)/waitq.o $(BUILD)/borrow.o $(BUILD)/proto.o

BINS      := $(BUILD)/sgd $(BUILD)/sg-launch $(BUILD)/sgctl $(BUILD)/step1_hello
TEST_BINS := $(BUILD)/unit_test $(BUILD)/forkn $(BUILD)/threadn $(BUILD)/bigmmap
EVAL_BINS := $(BUILD)/victim $(BUILD)/fsync_flood $(BUILD)/cheap_io $(BUILD)/fork_pressure \
             $(BUILD)/meta_storm $(BUILD)/bench_syscall

.PHONY: all test calibrate eval-bins evaluate diagnose clean

all: $(BINS)

# Wake-up latency diagnostics; root enables the per-stage tracing.
diagnose: all $(EVAL_BINS)
	sudo python3 eval/diagnose.py

eval-bins: $(EVAL_BINS)

$(BUILD)/%: eval/%.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

# See eval/README.md. Root enables the cgroup v2 baseline.
evaluate: all $(EVAL_BINS)
	python3 eval/run_eval.py

# Measure syscall costs on this machine (needs root for bpftrace).
calibrate: $(BUILD)/sgd
	mkdir -p costs
	sudo python3 tools/sg_calibrate.py -o costs/$$(uname -r).conf

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD)/sgd: $(BUILD)/sgd.o $(BUILD)/sgd_ctl.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/sg-launch: $(BUILD)/sg-launch.o $(CORE)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/sgctl: $(BUILD)/sgctl.o $(BUILD)/proto.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/step1_hello: $(BUILD)/step1_hello.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD)/unit_test: tests/unit_test.c $(CORE) $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/unit_test.c $(CORE)

$(BUILD)/forkn: tests/forkn.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/bigmmap: tests/bigmmap.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $<

$(BUILD)/threadn: tests/threadn.c | $(BUILD)
	$(CC) $(CFLAGS) -pthread -o $@ $<

$(BUILD):
	mkdir -p $@

test: all $(TEST_BINS)
	$(BUILD)/unit_test
	@if command -v python3 >/dev/null; then python3 tests/test_analyze.py && python3 tests/test_calibrate.py \
	   && python3 tests/test_wakeup_trace.py; \
	 else echo "SKIP  python tests (python3 not found)"; fi
	sh tests/step1_test.sh
	sh tests/integration_test.sh

clean:
	rm -rf $(BUILD)
