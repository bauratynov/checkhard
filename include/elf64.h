/*
 * elf64.h — minimal ELF64 loader for auditing.
 *
 * Self-contained: defines the subset of ELF structures and constants we
 * need so the tool builds on any host without <elf.h>. Validates
 * offsets / sizes before dereferencing; refuses malformed files.
 */
#ifndef CHECKHARD_ELF64_H
#define CHECKHARD_ELF64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- ELF constants (subset) ---------- */

#define EI_NIDENT    16
#define ELFMAG0      0x7f
#define ELFMAG1      'E'
#define ELFMAG2      'L'
#define ELFMAG3      'F'
#define ELFCLASS64   2
#define ELFDATA2LSB  1

#define ET_EXEC      2
#define ET_DYN       3

#define PT_LOAD       1
#define PT_DYNAMIC    2
#define PT_INTERP     3
#define PT_GNU_STACK  0x6474e551
#define PT_GNU_RELRO  0x6474e552

#define PF_X 1u
#define PF_W 2u
#define PF_R 4u

#define DT_NULL       0
#define DT_NEEDED     1
#define DT_STRTAB     5
#define DT_SYMTAB     6
#define DT_STRSZ      10
#define DT_SYMENT     11
#define DT_RPATH      15
#define DT_SYMBOLIC   16
#define DT_BIND_NOW   24
#define DT_RUNPATH    29
#define DT_FLAGS      30
#define DT_FLAGS_1    0x6ffffffb

#define DF_BIND_NOW   0x00000008
#define DF_1_NOW      0x00000001

#define SHT_NULL     0
#define SHT_PROGBITS 1
#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_DYNAMIC  6
#define SHT_NOBITS   8
#define SHT_DYNSYM   11

#define SHF_WRITE     (1u << 0)
#define SHF_ALLOC     (1u << 1)
#define SHF_EXECINSTR (1u << 2)

/* ---------- ELF64 structures ---------- */

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;   /* union with d_ptr in the spec; both are 64-bit. */
} Elf64_Dyn;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

/* ---------- parsed view ---------- */

typedef struct {
    const uint8_t   *map;       /* mmap base, read-only */
    size_t           size;      /* file size in bytes    */
    int              owns;      /* true if we must munmap on close */

    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;     /* may be NULL */
    size_t            phnum;
    const Elf64_Shdr *shdr;     /* may be NULL */
    size_t            shnum;

    const char       *shstrtab; /* section-header string table, may be NULL */

    const Elf64_Dyn  *dynamic;  /* dynamic section entries, may be NULL */
    size_t            dynnum;
    const char       *dynstr;   /* string table for dynsym / DT_NEEDED */
    size_t            dynstr_size;
    const Elf64_Sym  *dynsym;
    size_t            dynsym_count;
} elf64_t;

/* Map a file read-only, parse + validate.
 * Returns 0 on success. On failure returns -1 and sets errno; out is
 * left in a safe-to-close state. */
int  elf64_load(const char *path, elf64_t *out);

/* Parse a buffer already resident in memory (no mmap). The buffer must
 * outlive the elf64_t. Useful for unit tests. */
int  elf64_load_buffer(const uint8_t *buf, size_t size, elf64_t *out);

void elf64_close(elf64_t *e);

/* Accessors — return NULL if not present / out of range. */
const Elf64_Phdr *elf64_find_phdr(const elf64_t *e, uint32_t type);
const Elf64_Shdr *elf64_find_shdr(const elf64_t *e, const char *name);
const char       *elf64_dynstr(const elf64_t *e, uint64_t offset);

#ifdef __cplusplus
}
#endif

#endif /* CHECKHARD_ELF64_H */
