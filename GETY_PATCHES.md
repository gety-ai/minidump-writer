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

### Allow a custom Linux process backend

- Platform: Linux.
- Change: expose `MinidumpWriterConfig::set_process_backend` to choose the
  backend before initialization, and re-export `process_backend`.
- Why: Gety's collector supplies a backend that reads snapshot memory and
  preserves the original thread list without ptrace or freezing threads.
- Still needed: upstream only exposes built-in local and remote backends.
  Not proposed upstream yet.
- Used by: Gety memory diagnose, DEV-735.

### Index Linux thread names independently of unnamed threads

- Platform: Linux.
- Change: index only named threads when filling the thread-names stream.
  Output is unchanged when every thread has a name.
- Why: missing names otherwise cause out-of-bounds writes, corrupting the
  stream or panicking. Saved snapshot thread sets routinely include vanished
  threads whose names cannot be read.
- Still needed: upstream indexes the full thread list after allocating only
  named entries. Worth proposing upstream.
- Used by: Gety memory diagnose, DEV-735.

### Keep Linux threads whose contexts are unavailable

- Platform: Linux.
- Change: add the default-off `MinidumpWriterConfig::keep_threads_without_context`
  option. Keep threads when general registers cannot be read during suspension;
  if thread info cannot be read, write empty context and stack descriptors and
  record a soft error. The shared thread-list path covers x86, x86_64, ARM and
  AArch64. Default crash-path behavior is unchanged.
- Why: Gety's snapshot backend has no thread registers: it does not use ptrace
  or freeze threads. All original thread IDs must still appear in triage dumps.
  Per-thread status files can also be unavailable in the snapshot child's
  `/proc` view, so the fallback covers every `ThreadInfoError`, not only
  register failures.
- Still needed: upstream drops these threads on x86/x86_64 and treats failure
  to obtain general registers as a hard error on every supported architecture.
  Not proposed upstream yet.
- Used by: Gety memory diagnose, DEV-735.

## Dropped patches

### Relax crash-context requirement to 0.7

- Dropped when rebasing onto `59aad8d`.
- Why: upstream moved `crash-context` into this repository (0.8), and Gety's
  `crash-handling` fork moved to the 0.11 line that uses `crash-context` 0.8,
  so there is no longer a second `crash-context` instance to unify. Still
  available on the `crash-context-0.7` branch.

## Other branches

- `gety/minimal-process-access`: the Windows patch on top of 0.13.0
  (`37ba333`). Gety PR #1288 pins that commit; keep the branch until Gety
  moves to a rev on `main`.
- `crash-context-0.7`: the dropped patch above, kept for history.
