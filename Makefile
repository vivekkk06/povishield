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

eval-ablate: all               ## counterfactual permission ablation evaluation -> results/ablation_eval.json
> python3 -m evaluation.eval_ablation

eval-noisy: all                ## controlled noisy-policy ablation experiment -> results/noisy_ablation_eval.json
> python3 -m evaluation.eval_noisy_ablation

escape: all                    ## escape suite, run as root: sudo make escape
> python3 tests/escape/run_escape.py

resume-line:                   ## print resume bullet from measured results
> python3 -m evaluation.resume_line

demo: all                      ## attack demo
> bash demo/run_demo.sh

demo-cf: all                   ## counterfactual permission verification & ledger demo
> bash demo/run_counterfactual_demo.sh

watch: all                     ## watch directory, verify syntax & permissions on change
> python3 scripts/watch_and_verify.py --watch

watch-commit: all              ## watch directory, verify and auto-commit to main branch
> python3 scripts/watch_and_verify.py --watch --auto-commit

dashboard:                     ## live cgroup dashboard
> python3 dashboard/tui.py

deps:                          ## Fedora (dnf) or Ubuntu/Debian (apt)
> @if command -v dnf >/dev/null; then sudo dnf install -y gcc make libseccomp-devel python3 busybox git; \
> elif command -v apt-get >/dev/null; then sudo apt-get install -y build-essential libseccomp-dev python3 busybox-static git; \
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

.PHONY: asan fuzz lint verify docs
asan:                          ## build with AddressSanitizer + UBSan
> @mkdir -p build
> $(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -std=gnu11 -Iinclude $(shell find src -name '*.c') -o build/povishield-asan -lseccomp

fuzz: all asan                 ## mutation-fuzz the profile loader (plain + sanitized)
> python3 tests/fuzz_profile.py 500
> BIN=build/povishield-asan python3 tests/fuzz_profile.py 300

lint:                          ## static analysis (needs cppcheck)
> cppcheck --enable=warning,performance,portability --error-exitcode=1 --inline-suppr -Iinclude src

docs:                     ## regenerate docs/RESULTS.md from measured data
> python3 -m evaluation.make_docs

verify: all test fuzz          ## everything that needs no root
> @echo "verify OK (run: sudo make escape  for the escape matrix)"

.PHONY: test-root escape-full web audit dashboard-check final
test-root: all                 ## privileged runtime + rootfs tests (needs sudo)
> sudo env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_root_*.py' -v

escape-full: all               ## escape matrix incl. rootfs columns -> docs/escape-matrix.txt (needs sudo)
> sudo PS_ROOTFS=/tmp/ps-escape-rootfs bash tests/escape/make_rootfs.sh
> sudo env PS_ROOTFS=/tmp/ps-escape-rootfs PYTHONDONTWRITEBYTECODE=1 python3 tests/escape/run_escape.py 2>&1 | tee results/escape-matrix.txt
> cp results/escape-matrix.txt docs/escape-matrix.txt
> sudo chown -R $$USER:$$USER results docs

web:                           ## frontend production build
> cd frontend && npm ci && npm run build

audit:                         ## read-only repository audit -> results/audit.txt
> bash scripts/audit.sh

dashboard-check:               ## does the API show live data?
> python3 scripts/verify_dashboard.py

final: all                     ## everything, in the right order (quiet machine first, then the noisy tests)
> sudo -v
> $(MAKE) test
> $(MAKE) eval
> $(MAKE) verify
> $(MAKE) test-root
> $(MAKE) escape-full
> $(MAKE) docs
> $(MAKE) resume-line
