/*
 * elf64.c — ELF64 loader with bounds-checked pointer setup.
 *
 * The goal is safety on malformed inputs: every offset is checked
 * against the file size before we cast to a pointer. Nothing inside
 * elf64_t ever points outside the mapping.
 */

#include "elf64.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/mman.h>
#endif

/* --- safe pointer helpers --- */

static int in_bounds(const elf64_t *e, uint64_t off, uint64_t len)
{
    return off <= e->size && len <= e->size && off + len <= e->size;
}

static const void *at(const elf64_t *e, uint64_t off, uint64_t len)
{
    return in_bounds(e, off, len) ? (const void *)(e->map + off) : NULL;
}

/* --- parse --- */

static int parse(elf64_t *e)
{
    if (e->size < sizeof(Elf64_Ehdr)) { errno = EINVAL; return -1; }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)e->map;

    if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 ||
        eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) {
        errno = EINVAL; return -1;
    }
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_ident[5] != ELFDATA2LSB) {
        errno = ENOTSUP; return -1;
    }
    if (eh->e_ehsize   < sizeof(Elf64_Ehdr) ||
        eh->e_phentsize != sizeof(Elf64_Phdr) ||
        eh->e_shentsize != sizeof(Elf64_Shdr)) {
        errno = EINVAL; return -1;
    }

    e->ehdr = eh;

    /* program headers */
    if (eh->e_phnum) {
        uint64_t phsz = (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr);
        const void *p = at(e, eh->e_phoff, phsz);
        if (!p) { errno = EINVAL; return -1; }
        e->phdr  = (const Elf64_Phdr *)p;
        e->phnum = eh->e_phnum;
    }

    /* section headers */
    if (eh->e_shnum) {
        uint64_t shsz = (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr);
        const void *p = at(e, eh->e_shoff, shsz);
        if (!p) { errno = EINVAL; return -1; }
        e->shdr  = (const Elf64_Shdr *)p;
        e->shnum = eh->e_shnum;

        /* section-header string table */
        if (eh->e_shstrndx < eh->e_shnum) {
            const Elf64_Shdr *s = &e->shdr[eh->e_shstrndx];
            const void *p2 = at(e, s->sh_offset, s->sh_size);
            if (p2) e->shstrtab = (const char *)p2;
        }
    }

    /* dynamic section via PT_DYNAMIC */
    const Elf64_Phdr *pt_dyn = elf64_find_phdr(e, PT_DYNAMIC);
    if (pt_dyn) {
        uint64_t n     = pt_dyn->p_filesz / sizeof(Elf64_Dyn);
        uint64_t bytes = n * sizeof(Elf64_Dyn);
        const void *p  = at(e, pt_dyn->p_offset, bytes);
        if (p) {
            e->dynamic = (const Elf64_Dyn *)p;
            e->dynnum  = (size_t)n;
        }
    }

    /* dynstr / dynsym from .dynamic */
    if (e->dynamic) {
        uint64_t strtab_vaddr = 0, symtab_vaddr = 0;
        uint64_t strsz        = 0;
        for (size_t i = 0; i < e->dynnum; i++) {
            switch (e->dynamic[i].d_tag) {
            case DT_STRTAB: strtab_vaddr = e->dynamic[i].d_val; break;
            case DT_SYMTAB: symtab_vaddr = e->dynamic[i].d_val; break;
            case DT_STRSZ:  strsz        = e->dynamic[i].d_val; break;
            case DT_NULL:   i = e->dynnum;                      break;
            default: break;
            }
        }

        /* Translate virtual addresses to file offsets via PT_LOAD. */
        if (strtab_vaddr && e->phdr) {
            for (size_t i = 0; i < e->phnum; i++) {
                const Elf64_Phdr *ph = &e->phdr[i];
                if (ph->p_type != PT_LOAD) continue;
                if (strtab_vaddr >= ph->p_vaddr &&
                    strtab_vaddr <  ph->p_vaddr + ph->p_filesz) {
                    uint64_t off = ph->p_offset + (strtab_vaddr - ph->p_vaddr);
                    const void *p = at(e, off, strsz ? strsz : 1);
                    if (p) {
                        e->dynstr      = (const char *)p;
                        e->dynstr_size = strsz;
                    }
                    break;
                }
            }
        }

        if (symtab_vaddr && e->phdr && e->shdr) {
            for (size_t i = 0; i < e->phnum; i++) {
                const Elf64_Phdr *ph = &e->phdr[i];
                if (ph->p_type != PT_LOAD) continue;
                if (symtab_vaddr >= ph->p_vaddr &&
                    symtab_vaddr <  ph->p_vaddr + ph->p_filesz) {
                    uint64_t off = ph->p_offset + (symtab_vaddr - ph->p_vaddr);
                    /* We don't know SYMTAB length from .dynamic; use the
                     * matching section header to size it. */
                    for (size_t j = 0; j < e->shnum; j++) {
                        if (e->shdr[j].sh_type == SHT_DYNSYM) {
                            uint64_t bytes = e->shdr[j].sh_size;
                            const void *p = at(e, off, bytes);
                            if (p) {
                                e->dynsym       = (const Elf64_Sym *)p;
                                e->dynsym_count = bytes / sizeof(Elf64_Sym);
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    return 0;
}

int elf64_load_buffer(const uint8_t *buf, size_t size, elf64_t *out)
{
    memset(out, 0, sizeof(*out));
    out->map  = buf;
    out->size = size;
    out->owns = 0;
    return parse(out);
}

#if !defined(_WIN32)
int elf64_load(const char *path, elf64_t *out)
{
    memset(out, 0, sizeof(*out));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if (st.st_size <= 0)    { close(fd); errno = EINVAL; return -1; }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    out->map  = (const uint8_t *)map;
    out->size = (size_t)st.st_size;
    out->owns = 1;

    if (parse(out) < 0) {
        int e = errno;
        munmap((void *)out->map, out->size);
        memset(out, 0, sizeof(*out));
        errno = e;
        return -1;
    }
    return 0;
}
#else
int elf64_load(const char *path, elf64_t *out)
{
    (void)path; (void)out;
    errno = ENOSYS;
    return -1;
}
#endif

void elf64_close(elf64_t *e)
{
    if (!e || !e->map) return;
#if !defined(_WIN32)
    if (e->owns) {
        munmap((void *)e->map, e->size);
    }
#endif
    memset(e, 0, sizeof(*e));
}

const Elf64_Phdr *elf64_find_phdr(const elf64_t *e, uint32_t type)
{
    for (size_t i = 0; i < e->phnum; i++) {
        if (e->phdr[i].p_type == type) return &e->phdr[i];
    }
    return NULL;
}

const Elf64_Shdr *elf64_find_shdr(const elf64_t *e, const char *name)
{
    if (!e->shdr || !e->shstrtab) return NULL;
    for (size_t i = 0; i < e->shnum; i++) {
        const char *n = e->shstrtab + e->shdr[i].sh_name;
        if (strcmp(n, name) == 0) return &e->shdr[i];
    }
    return NULL;
}

const char *elf64_dynstr(const elf64_t *e, uint64_t offset)
{
    if (!e->dynstr || offset >= e->dynstr_size) return NULL;
    return e->dynstr + offset;
}
