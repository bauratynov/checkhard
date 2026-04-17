/*
 * format.c — audit report rendering.
 */

#include "checks.h"

#include <stdio.h>
#include <string.h>

static const char *pie_str(pie_result_t v)
{
    switch (v) {
    case PIE_YES: return "yes (PIE)";
    case PIE_DSO: return "shared object";
    default:      return "no";
    }
}

static const char *nx_str(nx_result_t v)
{
    switch (v) {
    case NX_ON:      return "enabled";
    case NX_OFF:     return "DISABLED";
    default:         return "unknown";
    }
}

static const char *relro_str(relro_result_t v)
{
    switch (v) {
    case RELRO_FULL:    return "full";
    case RELRO_PARTIAL: return "partial";
    default:            return "none";
    }
}

/* ANSI colour helpers: disabled if output is redirected. */
static int g_use_colour = 0;
void format_set_colour(int on) { g_use_colour = on; }

static const char *c_ok   (void) { return g_use_colour ? "\x1b[32m" : ""; }
static const char *c_warn (void) { return g_use_colour ? "\x1b[33m" : ""; }
static const char *c_bad  (void) { return g_use_colour ? "\x1b[31m" : ""; }
static const char *c_reset(void) { return g_use_colour ? "\x1b[0m"  : ""; }

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

void format_text(FILE *f, const audit_t *a);
void format_json(FILE *f, const audit_t *a, int first);

void format_text(FILE *f, const audit_t *a)
{
    fprintf(f, "%s%s%s\n", c_ok(), a->path, c_reset());

    const char *col;
    col = (a->pie == PIE_YES) ? c_ok()
        : (a->pie == PIE_DSO) ? c_ok() : c_bad();
    fprintf(f, "  PIE           : %s%s%s\n", col, pie_str(a->pie), c_reset());

    col = (a->nx == NX_ON)  ? c_ok()
        : (a->nx == NX_OFF) ? c_bad() : c_warn();
    fprintf(f, "  NX stack      : %s%s%s\n", col, nx_str(a->nx), c_reset());

    col = (a->relro == RELRO_FULL)    ? c_ok()
        : (a->relro == RELRO_PARTIAL) ? c_warn() : c_bad();
    fprintf(f, "  RELRO         : %s%s%s\n", col, relro_str(a->relro), c_reset());

    fprintf(f, "  stack canary  : %s%s%s\n",
            a->canary ? c_ok() : c_bad(),
            a->canary ? "present" : "missing",
            c_reset());

    fprintf(f, "  FORTIFY       : %s%s%s\n",
            a->fortify ? c_ok() : c_warn(),
            a->fortify ? "present" : "absent",
            c_reset());

    if (a->rpath_kind != RPATH_NONE) {
        fprintf(f, "  %-13s : %s%s%s\n",
                a->rpath_kind == RPATH_RUNPATH ? "RUNPATH" : "RPATH",
                c_warn(), a->rpath ? a->rpath : "(unreadable)", c_reset());
    } else {
        fprintf(f, "  RPATH/RUNPATH : %s(none)%s\n", c_ok(), c_reset());
    }

    fprintf(f, "  symbols       : %s%s%s\n",
            a->stripped ? c_ok() : c_warn(),
            a->stripped ? "stripped" : "retained",
            c_reset());

    if (a->rwx_count > 0) {
        fprintf(f, "  W+X segments  : %s%d (DANGEROUS)%s\n",
                c_bad(), a->rwx_count, c_reset());
    } else {
        fprintf(f, "  W+X segments  : %snone%s\n", c_ok(), c_reset());
    }
}

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if      (c == '"')  fputs("\\\"", f);
        else if (c == '\\') fputs("\\\\", f);
        else if (c == '\n') fputs("\\n",  f);
        else if (c == '\t') fputs("\\t",  f);
        else if (c <  0x20) fprintf(f, "\\u%04x", c);
        else                fputc(c, f);
    }
    fputc('"', f);
}

void format_json(FILE *f, const audit_t *a, int first)
{
    if (!first) fputc(',', f);
    fputs("\n  {", f);

    fputs("\"path\":",     f); json_str(f, a->path);           fputc(',', f);
    fputs("\"pie\":",      f); json_str(f, pie_str(a->pie));   fputc(',', f);
    fputs("\"nx\":",       f); json_str(f, nx_str(a->nx));     fputc(',', f);
    fputs("\"relro\":",    f); json_str(f, relro_str(a->relro)); fputc(',', f);
    fprintf(f, "\"canary\":%s,",   a->canary   ? "true" : "false");
    fprintf(f, "\"fortify\":%s,",  a->fortify  ? "true" : "false");
    fprintf(f, "\"stripped\":%s,", a->stripped ? "true" : "false");
    fprintf(f, "\"rwx_segments\":%d", a->rwx_count);

    if (a->rpath_kind == RPATH_RUNPATH) {
        fputs(",\"runpath\":", f);
        json_str(f, a->rpath ? a->rpath : "");
    } else if (a->rpath_kind == RPATH_RPATH) {
        fputs(",\"rpath\":", f);
        json_str(f, a->rpath ? a->rpath : "");
    }

    fputc('}', f);
}
