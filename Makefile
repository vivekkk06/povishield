.RECIPEPREFIX = >
CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11 -Iinclude
LDLIBS   = -lseccomp
BUILD    = build
SRC      = $(shell find src -name '*.c')
BIN      = $(BUILD)/povishield
ESC_SRC  = $(wildcard tests/escape/*.c)
ESC_BIN  = $(patsubst tests/escape/%.c,$(BUILD)/escape/%,$(ESC_SRC))

.PHONY: all clean test eval escape resume-line demo dashboard deps help

all: $(BIN) $(ESC_BIN) $(BUILD)/vuln_viewer

$(BIN): $(SRC) include/povishield.h
> @mkdir -p $(BUILD)
> $(CC) $(CFLAGS) $(SRC) -o $@ $(LDLIBS)

$(BUILD)/escape/%: tests/escape/%.c
> @mkdir -p $(dir $@)
> $(CC) -O0 -Wall $< -o $@

$(BUILD)/vuln_viewer: demo/vuln_viewer.c
> @mkdir -p $(BUILD)
> $(CC) -O0 -Wall $< -o $@

test: all                      ## unit tests (no root needed)
> python3 -m unittest discover -s tests -v

eval: all                      ## full benchmark -> results/results.json + report.md
> python3 -m evaluation.run_eval

escape: all                    ## escape suite, run as root: sudo make escape
> python3 tests/escape/run_escape.py

resume-line:                   ## print resume bullet from measured results
> python3 -m evaluation.resume_line

demo: all                      ## attack demo
> bash demo/run_demo.sh

dashboard:                     ## live cgroup dashboard
> python3 dashboard/tui.py

deps:                          ## Fedora (dnf) or Ubuntu/Debian (apt)
> @if command -v dnf >/dev/null; then sudo dnf install -y gcc make libseccomp-devel python3 busybox git; \
> elif command -v apt-get >/dev/null; then sudo dnf install -y gcc make libseccomp-devel python3 busybox git; \
> else echo "install: gcc make libseccomp headers python3>=3.11 busybox"; fi

clean:
> rm -rf $(BUILD) results/*.json results/*.md results/profiles

help:
> @grep -E '^[a-z-]+:.*##' Makefile

.PHONY: check check-web
check: all test                ## safe non-root checks (never runs escape tests)
> bash tests/check_safe.sh

check-web:                     ## API startup + endpoints + frontend production build
> bash tests/check_web.sh
