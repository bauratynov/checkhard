# checkhard — ELF64 hardening auditor
# Targets:
#   make            build the checkhard binary
#   make test       run unit + integration tests
#   make clean

CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE
LDFLAGS  +=
LDLIBS   +=

SRC := src/elf64.c src/checks.c src/format.c src/main.c
OBJ := $(SRC:.c=.o)
BIN := checkhard

.PHONY: all test clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BIN)
	$(MAKE) -C tests run

clean:
	rm -f $(OBJ) $(BIN)
	$(MAKE) -C tests clean

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)
