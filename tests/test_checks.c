/*
 * test_checks.c — unit tests for the checks that operate on program
 * headers only (no dynamic-section setup required).
 *
 * We hand-assemble a tiny valid ELF64 in a byte buffer, run the
 * loader on it via elf64_load_buffer, and inspect the check results.
 * Checks that depend on dynsym / dynstr (canary, FORTIFY, RPATH,
 * RELRO-full) are exercised by the integration script against real
 * toolchain output.
 */

#include "checks.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int fails  = 0;
static int passes = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++;  printf("  [FAIL] %s\n", label); }                    \
    } while (0)

/* Build a minimal ELF64 in buf[]. Returns bytes written. */
static size_t build_elf(uint8_t *buf, size_t cap,
                        uint16_t e_type,
                        const Elf64_Phdr *phdrs, size_t nph)
{
    size_t phoff = sizeof(Elf64_Ehdr);
    size_t total = phoff + nph * sizeof(Elf64_Phdr);
    if (total > cap) return 0;

    memset(buf, 0, total);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    eh->e_ident[0] = ELFMAG0;
    eh->e_ident[1] = ELFMAG1;
    eh->e_ident[2] = ELFMAG2;
    eh->e_ident[3] = ELFMAG3;
    eh->e_ident[4] = ELFCLASS64;
    eh->e_ident[5] = ELFDATA2LSB;
    eh->e_ident[6] = 1; /* EV_CURRENT */
    eh->e_type      = e_type;
    eh->e_machine   = 62; /* EM_X86_64 */
    eh->e_version   = 1;
    eh->e_ehsize    = sizeof(Elf64_Ehdr);
    eh->e_phentsize = sizeof(Elf64_Phdr);
    eh->e_phnum     = (uint16_t)nph;
    eh->e_shentsize = sizeof(Elf64_Shdr);
    eh->e_phoff     = phoff;

    Elf64_Phdr *ph = (Elf64_Phdr *)(buf + phoff);
    memcpy(ph, phdrs, nph * sizeof(Elf64_Phdr));
    return total;
}

static void test_pie_exec(void)
{
    printf("check_pie on ET_EXEC\n");
    Elf64_Phdr ph = {0};
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_EXEC, &ph, 1);
    elf64_t e;
    CHECK(elf64_load_buffer(buf, n, &e) == 0, "loader accepts ET_EXEC");
    CHECK(check_pie(&e) == PIE_NO, "PIE_NO for ET_EXEC");
}

static void test_pie_dyn_with_interp(void)
{
    printf("check_pie on ET_DYN + PT_INTERP\n");
    Elf64_Phdr ph[2] = {
        { .p_type = PT_INTERP, .p_flags = PF_R,           },
        { .p_type = PT_LOAD,   .p_flags = PF_R | PF_X,    },
    };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_DYN, ph, 2);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_pie(&e) == PIE_YES, "PIE_YES for ET_DYN + PT_INTERP");
}

static void test_pie_dso(void)
{
    printf("check_pie on shared library (ET_DYN, no PT_INTERP)\n");
    Elf64_Phdr ph = { .p_type = PT_LOAD, .p_flags = PF_R | PF_X };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_DYN, &ph, 1);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_pie(&e) == PIE_DSO, "PIE_DSO for ET_DYN without interp");
}

static void test_nx_on_off_unknown(void)
{
    printf("check_nx with and without GNU_STACK\n");
    /* no GNU_STACK */
    Elf64_Phdr ph_none = { .p_type = PT_LOAD, .p_flags = PF_R | PF_X };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_EXEC, &ph_none, 1);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_nx(&e) == NX_UNKNOWN, "NX_UNKNOWN without GNU_STACK");

    /* GNU_STACK without PF_X → NX on */
    Elf64_Phdr ph_on[2] = {
        { .p_type = PT_LOAD,      .p_flags = PF_R | PF_X },
        { .p_type = PT_GNU_STACK, .p_flags = PF_R | PF_W },
    };
    n = build_elf(buf, sizeof buf, ET_EXEC, ph_on, 2);
    elf64_load_buffer(buf, n, &e);
    CHECK(check_nx(&e) == NX_ON, "NX_ON when GNU_STACK lacks PF_X");

    /* GNU_STACK with PF_X → NX off (bad) */
    Elf64_Phdr ph_off[2] = {
        { .p_type = PT_LOAD,      .p_flags = PF_R | PF_X },
        { .p_type = PT_GNU_STACK, .p_flags = PF_R | PF_W | PF_X },
    };
    n = build_elf(buf, sizeof buf, ET_EXEC, ph_off, 2);
    elf64_load_buffer(buf, n, &e);
    CHECK(check_nx(&e) == NX_OFF, "NX_OFF when GNU_STACK has PF_X");
}

static void test_rwx_segments(void)
{
    printf("check_rwx_segments on mixed loads\n");
    Elf64_Phdr ph[3] = {
        { .p_type = PT_LOAD, .p_flags = PF_R | PF_X         }, /* text  */
        { .p_type = PT_LOAD, .p_flags = PF_R | PF_W         }, /* data  */
        { .p_type = PT_LOAD, .p_flags = PF_R | PF_W | PF_X  }, /* BAD   */
    };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_EXEC, ph, 3);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_rwx_segments(&e) == 1, "one W+X segment counted");

    /* two RWX segments */
    ph[0].p_flags = PF_R | PF_W | PF_X;
    n = build_elf(buf, sizeof buf, ET_EXEC, ph, 3);
    elf64_load_buffer(buf, n, &e);
    CHECK(check_rwx_segments(&e) == 2, "two W+X segments counted");
}

static void test_relro_none(void)
{
    printf("check_relro without PT_GNU_RELRO\n");
    Elf64_Phdr ph = { .p_type = PT_LOAD, .p_flags = PF_R | PF_X };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_EXEC, &ph, 1);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_relro(&e) == RELRO_NONE, "RELRO_NONE");
}

static void test_relro_partial(void)
{
    printf("check_relro with PT_GNU_RELRO (no BIND_NOW)\n");
    Elf64_Phdr ph[2] = {
        { .p_type = PT_LOAD,      .p_flags = PF_R | PF_X },
        { .p_type = PT_GNU_RELRO, .p_flags = PF_R         },
    };
    uint8_t buf[4096];
    size_t n = build_elf(buf, sizeof buf, ET_EXEC, ph, 2);
    elf64_t e;
    elf64_load_buffer(buf, n, &e);
    CHECK(check_relro(&e) == RELRO_PARTIAL, "RELRO_PARTIAL without BIND_NOW");
}

static void test_loader_rejects_garbage(void)
{
    printf("elf64_load_buffer rejects garbage\n");
    uint8_t garbage[128];
    memset(garbage, 0xaa, sizeof garbage);
    elf64_t e;
    CHECK(elf64_load_buffer(garbage, sizeof garbage, &e) < 0,
          "non-ELF magic rejected");
}

int main(void)
{
    test_pie_exec();
    test_pie_dyn_with_interp();
    test_pie_dso();
    test_nx_on_off_unknown();
    test_rwx_segments();
    test_relro_none();
    test_relro_partial();
    test_loader_rejects_garbage();

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
