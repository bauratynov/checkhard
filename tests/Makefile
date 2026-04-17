CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O0 -g
CFLAGS   += $(CSTD) $(WARN) $(OPT) -I../include -D_GNU_SOURCE

TESTS := test_checks

.PHONY: all run clean fixtures integration
all: $(TESTS)

test_checks: test_checks.c ../src/elf64.c ../src/checks.c
	$(CC) $(CFLAGS) -o $@ $^

run: $(TESTS)
	@echo "==> unit tests"
	@./test_checks
	@echo
	@echo "==> integration tests"
	@./integration.sh

fixtures:
	./fixtures/build.sh

integration:
	./integration.sh

clean:
	rm -f $(TESTS)
	$(MAKE) -C fixtures clean 2>/dev/null || rm -f fixtures/bin_*
