/*
 * checks.h — hardening audit checks for an ELF64 binary.
 *
 * Every check takes a parsed elf64_t and produces a small enum result.
 * Results are pure functions: they allocate nothing and touch no global
 * state, so they can be unit-tested on hand-crafted in-memory binaries.
 */
#ifndef CHECKHARD_CHECKS_H
#define CHECKHARD_CHECKS_H

#include "elf64.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Position-independent executable. PIE on modern binaries = ET_DYN
 * combined with an interpreter (PT_INTERP) or the shared DF flags.
 * A shared library (ET_DYN with no PT_INTERP) counts as PIE too. */
typedef enum {
    PIE_NO       = 0,   /* ET_EXEC */
    PIE_DSO      = 1,   /* ET_DYN, library */
    PIE_YES      = 2    /* ET_DYN executable */
} pie_result_t;

typedef enum {
    NX_UNKNOWN   = 0,   /* no PT_GNU_STACK entry */
    NX_OFF       = 1,   /* GNU_STACK flags include PF_X */
    NX_ON        = 2
} nx_result_t;

typedef enum {
    RELRO_NONE    = 0,
    RELRO_PARTIAL = 1,
    RELRO_FULL    = 2
} relro_result_t;

typedef enum {
    RPATH_NONE    = 0,
    RPATH_RUNPATH = 1,
    RPATH_RPATH   = 2
} rpath_kind_t;

pie_result_t     check_pie(const elf64_t *e);
nx_result_t      check_nx(const elf64_t *e);
relro_result_t   check_relro(const elf64_t *e);

/* Fills *out_path with the first matching DT_RPATH / DT_RUNPATH string,
 * or NULL if none. Return value indicates which flavour was found
 * (RUNPATH takes precedence over RPATH if both are present). */
rpath_kind_t     check_rpath(const elf64_t *e, const char **out_path);

bool             check_canary (const elf64_t *e);   /* __stack_chk_fail */
bool             check_fortify(const elf64_t *e);   /* *_chk symbols    */
bool             check_stripped(const elf64_t *e);  /* no SHT_SYMTAB    */

/* Count segments that are both writable and executable. */
int              check_rwx_segments(const elf64_t *e);

#ifdef __cplusplus
}
#endif

#endif /* CHECKHARD_CHECKS_H */
