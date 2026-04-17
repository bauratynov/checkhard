/*
 * main.c — checkhard CLI driver.
 *
 * Usage:
 *   checkhard [--json] [--no-colour] <binary> [<binary> ...]
 *
 * Exit codes:
 *   0  every audited file passed the strict policy
 *      (PIE yes / NX on / RELRO full / canary / no RWX)
 *   1  at least one file tripped a hard warning
 *   2  bad invocation / unreadable file
 */

#include "checks.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
  #include <unistd.h>
#endif

/* duplicated here so main.c doesn't drag extra public headers */
typedef struct {
    const char    *path;
    pie_result_t   pie;
    nx_result_t    nx;
    relro_result_t relro;
    rpath_kind_t   rpath_kind;
    const char    *rpath;
    int            canary;
    int            fortify;
    int            stripped;
    int            rwx_count;
} audit_t;

void format_set_colour(int on);
void format_text(FILE *f, const audit_t *a);
void format_json(FILE *f, const audit_t *a, int first);

static int policy_fail(const audit_t *a)
{
    if (a->pie != PIE_YES && a->pie != PIE_DSO) return 1;
    if (a->nx  != NX_ON)                        return 1;
    if (a->relro != RELRO_FULL)                 return 1;
    if (!a->canary)                             return 1;
    if (a->rwx_count > 0)                       return 1;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
"checkhard — ELF64 hardening auditor\n"
"\n"
"Usage:\n"
"  %s [options] <elf64> [<elf64> ...]\n"
"\n"
"Options:\n"
"      --json            emit JSON array instead of text\n"
"      --no-colour       disable ANSI colours in text output\n"
"  -h, --help            this message\n"
"\n"
"Exit codes:\n"
"  0  every file passes the strict policy\n"
"  1  at least one file fails\n"
"  2  bad invocation / unreadable file\n",
    prog);
}

int main(int argc, char **argv)
{
    int json       = 0;
    int colour     = 0;
    int file_start = 1;

#if !defined(_WIN32)
    colour = isatty(1);
#endif

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--json") == 0)          { json = 1;  file_start = i + 1; continue; }
        if (strcmp(a, "--no-colour") == 0 ||
            strcmp(a, "--no-color") == 0)      { colour = 0; file_start = i + 1; continue; }
        if (strcmp(a, "--colour") == 0 ||
            strcmp(a, "--color") == 0)         { colour = 1; file_start = i + 1; continue; }
        if (strcmp(a, "-h") == 0 ||
            strcmp(a, "--help") == 0)          { usage(argv[0]); return 0; }
        if (a[0] == '-')                       { usage(argv[0]); return 2; }
        break;
    }

    if (file_start >= argc) { usage(argv[0]); return 2; }

    format_set_colour(colour);

    int any_fail = 0;
    int first    = 1;
    if (json) fputc('[', stdout);

    for (int i = file_start; i < argc; i++) {
        elf64_t e;
        if (elf64_load(argv[i], &e) < 0) {
            fprintf(stderr, "checkhard: %s: %s\n", argv[i], strerror(errno));
            any_fail = 1;
            continue;
        }

        audit_t a;
        memset(&a, 0, sizeof(a));
        a.path       = argv[i];
        a.pie        = check_pie(&e);
        a.nx         = check_nx(&e);
        a.relro      = check_relro(&e);
        a.rpath_kind = check_rpath(&e, &a.rpath);
        a.canary     = check_canary(&e);
        a.fortify    = check_fortify(&e);
        a.stripped   = check_stripped(&e);
        a.rwx_count  = check_rwx_segments(&e);

        if (json) {
            format_json(stdout, &a, first);
            first = 0;
        } else {
            if (!first) fputc('\n', stdout);
            format_text(stdout, &a);
            first = 0;
        }

        if (policy_fail(&a)) any_fail = 1;
        elf64_close(&e);
    }

    if (json) fputs("\n]\n", stdout);
    else      fputc('\n',    stdout);

    return any_fail ? 1 : 0;
}
