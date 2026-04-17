# Security Policy

## Scope

`checkhard` is a defensive audit tool. It reads ELF64 binaries
read-only and reports their hardening posture. It does not modify
binaries, does not load them, does not invoke their dynamic linker,
does not write anywhere outside stdout / stderr.

## Reporting a vulnerability

If you find a security bug — memory safety issue in the ELF loader,
misleading verdict that hides a genuine hardening failure, or a parser
panic on a crafted malicious ELF — please email the maintainer rather
than opening a public issue:

**Baurzhan Atynov** — `bauratynov@gmail.com`

Please include:
- issue description and impact,
- minimal reproducer (the ELF file that triggers the bug, zipped),
- affected commit / version,
- expected correct behaviour.

You will get a response within 72 hours. Fixes are prioritised over
features.

## Threat model

- **Malformed ELF parse**: every offset in `src/elf64.c` is validated
  against file size before dereferencing. No raw casts without a prior
  bounds check.
- **False positives / negatives**: audit results are best-effort.
  Dynamic-symbol-based checks (canary, FORTIFY) rely on the library's
  conventional symbol names. Non-libc libc replacements may emit
  different names; we document that in the README.
- **Exit-code contract**: policy failures return 1, bad invocations
  return 2. Callers can rely on this for CI gating.

## Out of scope

- Behavior on non-x86-64 ELF (e.g., ARM64) — `ELFCLASS64 + ELFDATA2LSB`
  files parse, but the *checks* assume x86-64 semantics.
- Files that are not ELF (Mach-O, PE, scripts) — they are rejected at
  load time.
- Runtime hardening (SELinux, AppArmor, seccomp-bpf profiles). Those
  are a separate concern; `checkhard` inspects the static binary only.
