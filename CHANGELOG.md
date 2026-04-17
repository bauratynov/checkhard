# Changelog

All notable changes to `checkhard` are listed here. This project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-17

Initial public release.

### Added
- **ELF64 loader** (`src/elf64.c`). Bounds-checked ELF64 parsing;
  resolves dynamic section, dynstr, and dynsym via PT_LOAD virtual
  address mapping. Rejects malformed inputs before dereferencing.
- **Eight hardening checks** (`src/checks.c`):
  PIE, NX stack, RELRO level, stack canary, FORTIFY source,
  RPATH / RUNPATH, stripped symbols, W+X segments.
- **Text + JSON output**. ANSI colour when stdout is a TTY;
  `--no-colour` to force off.
- **Exit-code contract**: `0` strict pass, `1` policy violation,
  `2` bad invocation / unreadable file.
- **Unit tests**. Hand-assembled ELF64 buffers exercise the
  header-based checks.
- **Integration tests**. `tests/fixtures/build.sh` compiles four
  binaries with contrasting hardening flag sets; `integration.sh`
  asserts the JSON verdict for each.
- **CI**. GitHub Actions: gcc + clang on ubuntu-22.04 / 24.04,
  cppcheck static analysis, AddressSanitizer + UBSan unit tests.

### Known limitations
- Checks assume x86-64 semantics (NX, PF_X etc. are universal, but
  stack-canary symbol names are glibc-flavoured).
- No ARM64 / RISC-V support yet — the loader accepts them, but the
  checks are not audited for those ABIs.
- No inspection of CFI / shadow-stack / BTI markers. Tracked for 0.2.

### Next
- 0.2.0: CET IBT (`NT_GNU_PROPERTY_X86_FEATURE_1_AND`) and CET shadow
  stack detection.
- 0.2.0: section entropy scan (packed / obfuscated detection).
- 0.3.0: ARM64 PAC / BTI property parsing.
