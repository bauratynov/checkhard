# checkhard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: C99](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform: Linux x86-64](https://img.shields.io/badge/Platform-Linux%20x86__64-green.svg)](https://refspecs.linuxfoundation.org/elf/)

ELF64 hardening auditor in pure C99. Reports PIE / NX / RELRO /
stack-canary / FORTIFY / RPATH / RWX-segment status on any x86-64
ELF64 binary, with text or JSON output and non-zero exit on policy
violation. One source tree, zero external dependencies.

> **Status:** v0.1.0 — loader + 8 checks + text/JSON CLI + unit +
> integration tests + CI. See [CHANGELOG.md](CHANGELOG.md).

---

## Why

`checksec.sh` exists, but it's a bash script built on `readelf`.
Shipping this as a static C99 binary makes it something you can drop
onto a locked-down host with no Python, no shell extensions, no
coreutils. It also gives you predictable exit codes for CI wiring.

## Checks

| Check        | Verdict meaning                                              |
|--------------|--------------------------------------------------------------|
| PIE          | ET_DYN + PT_INTERP → PIE; ET_DYN w/o interp → shared library |
| NX stack     | PT_GNU_STACK without PF_X → enabled                          |
| RELRO        | PT_GNU_RELRO + DT_BIND_NOW → full; PT_GNU_RELRO → partial    |
| Stack canary | `__stack_chk_fail` present in dynsym                         |
| FORTIFY      | any `*_chk` symbol in dynsym                                 |
| RPATH        | DT_RPATH / DT_RUNPATH value + kind                           |
| Stripped     | presence of `.symtab` (SHT_SYMTAB)                           |
| W+X segments | any PT_LOAD with both PF_W and PF_X                          |

## Build

```bash
make           # build ./checkhard
make test      # run tests (sprint 2)
```

## Usage

```bash
$ checkhard /bin/ls
/bin/ls
  PIE           : yes (PIE)
  NX stack      : enabled
  RELRO         : full
  stack canary  : present
  FORTIFY       : present
  RPATH/RUNPATH : (none)
  symbols       : stripped
  W+X segments  : none

$ checkhard --json /bin/ls /bin/bash
[
  {"path":"/bin/ls","pie":"yes (PIE)","nx":"enabled","relro":"full","canary":true,...},
  {"path":"/bin/bash","pie":"yes (PIE)","nx":"enabled","relro":"full","canary":true,...}
]

$ checkhard ./insecure_binary || echo "policy violation"
```

### Exit codes

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | every file passed the strict policy (PIE, NX, full RELRO, canary, no RWX) |
| 1    | at least one file tripped a hard warning                              |
| 2    | bad invocation or unreadable file                                     |

Use in CI:

```yaml
- run: checkhard dist/*.so dist/my-service
```

## Layout

```
checkhard/
├── LICENSE
├── Makefile
├── README.md
├── include/
│   ├── elf64.h
│   └── checks.h
├── src/
│   ├── elf64.c      # bounds-checked ELF64 loader
│   ├── checks.c     # PIE/NX/RELRO/canary/FORTIFY/RPATH/RWX
│   ├── format.c     # text + JSON
│   └── main.c       # CLI
└── tests/           # sprint 2
```

## Roadmap

- [x] Sprint 1: ELF64 loader + 8 checks + CLI + text/JSON
- [x] Sprint 2: unit tests (hand-crafted in-memory ELFs) + fixture builder
- [x] Sprint 3: CI (gcc+clang, cppcheck, ASan/UBSan), v0.1.0
- [ ] Sprint 4: CET IBT / shadow-stack (NT_GNU_PROPERTY_*)
- [ ] Sprint 5: section entropy scan (packed / obfuscated detection)

## References

- [System V Application Binary Interface, gABI](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
- [checksec.sh](https://github.com/slimm609/checksec.sh) — the bash original.
- `readelf -d`, `readelf -l` — reference output for hand-verification.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Baurzhan Atynov** — [bauratynov@gmail.com](mailto:bauratynov@gmail.com)
