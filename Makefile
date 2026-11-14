CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE

BUILD := build
REPORT_SRC := reports/report_status.c reports/my_reports.c
REPORT_HDR := reports/report_status.h reports/my_reports.h

.PHONY: all test clean

all: $(BUILD)/reportctl

$(BUILD):
	mkdir -p $@

$(BUILD)/reportctl: reports/reportctl.c $(REPORT_SRC) $(REPORT_HDR) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ reports/reportctl.c $(REPORT_SRC)

$(BUILD)/test_report_status: reports/tests/test_report_status.c $(REPORT_SRC) $(REPORT_HDR) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ reports/tests/test_report_status.c $(REPORT_SRC)

test: $(BUILD)/test_report_status
	./$(BUILD)/test_report_status

clean:
	rm -rf $(BUILD)
