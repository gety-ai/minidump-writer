# Gety patches

This fork carries the patches Gety needs on top of upstream
[rust-minidump/minidump-writer](https://github.com/rust-minidump/minidump-writer).
Every patch listed here is a separate commit on `main`; keep this file in sync
when rebasing, adding or dropping one.

Gety pins this fork by commit in its workspace `Cargo.toml`. `crash-context`
lives in the same repository and must be patched from the same rev as
`minidump-writer`, otherwise `minidump-writer` and `crash-handler` see two
distinct `CrashContext` types.

## Base

Upstream `main` at `59aad8d` (2026-10-14), 91 unreleased commits after 0.13.0.

## Carried patches

### Open external processes with only the rights MiniDumpWriteDump needs

- Platform: Windows.
- Change: `MinidumpWriter::dump_crash_context` opens the crashed process with
  `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, plus `PROCESS_DUP_HANDLE` when
  the dump type includes handle data, instead of `PROCESS_ALL_ACCESS`.
- Why: security products deny or strip all-access handles to other processes,
  which made the crash reporter fail to write any dump. Without
  `PROCESS_DUP_HANDLE`, dbghelp silently drops the handle stream; the
  `dump_external_process_with_handle_data` test guards that.
- Still needed: upstream `src/windows` is unchanged since 0.13.0 and still
  requests `PROCESS_ALL_ACCESS`. Not proposed upstream yet.
- Used by: Gety crash reporter (gety PR #1288).

## Dropped patches

### Relax crash-context requirement to 0.7

- Dropped when rebasing onto `59aad8d`.
- Why: upstream moved `crash-context` into this repository (0.8), and Gety's
  `crash-handling` fork moved to the 0.11 line that uses `crash-context` 0.8,
  so there is no longer a second `crash-context` instance to unify. Still
  available on the `crash-context-0.7` branch.

## Planned

- Linux: a public `MinidumpWriter::set_process_backend` entry point plus a
  re-export of `process_backend`, so a caller can supply its own
  `process_backend::Backend` (registers recorded at freeze time, memory read
  from a snapshot). Needed by Gety's memory diagnose feature.

## Other branches

- `gety/minimal-process-access`: the Windows patch on top of 0.13.0
  (`37ba333`). Gety PR #1288 pins that commit; keep the branch until Gety
  moves to a rev on `main`.
- `crash-context-0.7`: the dropped patch above, kept for history.
