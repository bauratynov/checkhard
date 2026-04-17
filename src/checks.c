/*
 * checks.c — hardening audit heuristics.
 *
 * Designed so each function is independently testable: no globals, no
 * allocation, no I/O. Every inspection goes through the validated
 * pointers in elf64_t.
 */

#include "checks.h"

#include <string.h>

/* ------------------------------------------------------------------
 * PIE
 * ------------------------------------------------------------------
 * An executable is position-independent if it is ET_DYN and has
 * PT_INTERP (shared objects are also ET_DYN but have no interpreter).
 */
pie_result_t check_pie(const elf64_t *e)
{
    if (!e->ehdr) return PIE_NO;
    if (e->ehdr->e_type == ET_EXEC) return PIE_NO;
    if (e->ehdr->e_type == ET_DYN) {
        if (elf64_find_phdr(e, PT_INTERP)) return PIE_YES;
        return PIE_DSO;
    }
    return PIE_NO;
}

/* ------------------------------------------------------------------
 * NX (non-executable stack)
 * ------------------------------------------------------------------
 * Linux marks the stack according to the PT_GNU_STACK program header.
 * PF_X set on that header means the stack is executable (bad); absent
 * or without PF_X means the kernel will map the stack non-executable.
 */
nx_result_t check_nx(const elf64_t *e)
{
    const Elf64_Phdr *p = elf64_find_phdr(e, PT_GNU_STACK);
    if (!p) return NX_UNKNOWN;
    return (p->p_flags & PF_X) ? NX_OFF : NX_ON;
}

/* ------------------------------------------------------------------
 * RELRO
 * ------------------------------------------------------------------
 * PT_GNU_RELRO present               -> partial RELRO
 * PT_GNU_RELRO + (DT_BIND_NOW OR
 *   DT_FLAGS & DF_BIND_NOW OR
 *   DT_FLAGS_1 & DF_1_NOW)           -> full RELRO
 */
relro_result_t check_relro(const elf64_t *e)
{
    if (!elf64_find_phdr(e, PT_GNU_RELRO)) return RELRO_NONE;

    int bind_now = 0;
    for (size_t i = 0; i < e->dynnum; i++) {
        int64_t tag = e->dynamic[i].d_tag;
        if (tag == DT_NULL) break;
        if (tag == DT_BIND_NOW) bind_now = 1;
        if (tag == DT_FLAGS    && (e->dynamic[i].d_val & DF_BIND_NOW)) bind_now = 1;
        if (tag == DT_FLAGS_1  && (e->dynamic[i].d_val & DF_1_NOW))    bind_now = 1;
    }
    return bind_now ? RELRO_FULL : RELRO_PARTIAL;
}

/* ------------------------------------------------------------------
 * RPATH / RUNPATH
 * ------------------------------------------------------------------
 * Either is a code smell: both embed library search paths into the
 * binary. RUNPATH is honoured after LD_LIBRARY_PATH, RPATH before it;
 * RUNPATH is the modern replacement but equally audit-worthy.
 */
rpath_kind_t check_rpath(const elf64_t *e, const char **out_path)
{
    if (out_path) *out_path = NULL;
    if (!e->dynamic) return RPATH_NONE;

    uint64_t rpath = 0, runpath = 0;
    for (size_t i = 0; i < e->dynnum; i++) {
        int64_t tag = e->dynamic[i].d_tag;
        if (tag == DT_NULL) break;
        if (tag == DT_RPATH)   rpath   = e->dynamic[i].d_val;
        if (tag == DT_RUNPATH) runpath = e->dynamic[i].d_val;
    }
    if (runpath) {
        if (out_path) *out_path = elf64_dynstr(e, runpath);
        return RPATH_RUNPATH;
    }
    if (rpath) {
        if (out_path) *out_path = elf64_dynstr(e, rpath);
        return RPATH_RPATH;
    }
    return RPATH_NONE;
}

/* ------------------------------------------------------------------
 * Helper: look for a dynamic symbol whose name equals `needle` or ends
 * with suffix `suffix`.
 * ------------------------------------------------------------------ */
static bool dynsym_has(const elf64_t *e, const char *needle, const char *suffix)
{
    if (!e->dynsym || !e->dynstr) return false;
    for (size_t i = 0; i < e->dynsym_count; i++) {
        const char *n = elf64_dynstr(e, e->dynsym[i].st_name);
        if (!n || !*n) continue;
        if (needle && strcmp(n, needle) == 0) return true;
        if (suffix) {
            size_t ln = strlen(n), ls = strlen(suffix);
            if (ln >= ls && strcmp(n + ln - ls, suffix) == 0) return true;
        }
    }
    return false;
}

bool check_canary(const elf64_t *e)
{
    return dynsym_has(e, "__stack_chk_fail", NULL) ||
           dynsym_has(e, "__stack_chk_fail_local", NULL);
}

bool check_fortify(const elf64_t *e)
{
    /* Fortified libc wrappers all end in "_chk" — memcpy_chk,
     * __printf_chk, __read_chk, ... */
    return dynsym_has(e, NULL, "_chk");
}

bool check_stripped(const elf64_t *e)
{
    if (!e->shdr) return true;
    for (size_t i = 0; i < e->shnum; i++) {
        if (e->shdr[i].sh_type == SHT_SYMTAB) return false;
    }
    return true;
}

int check_rwx_segments(const elf64_t *e)
{
    int count = 0;
    for (size_t i = 0; i < e->phnum; i++) {
        if (e->phdr[i].p_type != PT_LOAD) continue;
        uint32_t f = e->phdr[i].p_flags;
        if ((f & PF_W) && (f & PF_X)) count++;
    }
    return count;
}
