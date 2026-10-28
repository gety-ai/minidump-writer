#![cfg(any(target_os = "linux", target_os = "android"))]

use minidump::{
    Minidump, MinidumpException, MinidumpMemoryList, MinidumpSystemInfo, MinidumpThreadList,
    MinidumpThreadNames,
};
use minidump_writer::{
    minidump_writer::MinidumpWriterConfig,
    process_backend::{self, Backend, Result, local, regs::*},
};
use std::{cell::Cell, ffi::CStr, rc::Rc};

mod common;

#[derive(Debug)]
struct TestBackend {
    local: local::Backend,
    used: Rc<Cell<bool>>,
    deny_registers: bool,
    snapshot: Option<Snapshot>,
}

#[derive(Debug)]
struct Snapshot {
    threads: Vec<libc::pid_t>,
    vanished: Vec<libc::pid_t>,
    stat: Vec<u8>,
}

#[derive(Debug)]
enum TestFileReader {
    Local(local::FileReader),
    Saved(std::io::Cursor<Vec<u8>>),
}

impl process_backend::FileReader for TestFileReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Local(reader) => process_backend::FileReader::read(reader, buf),
            Self::Saved(reader) => Ok(std::io::Read::read(reader, buf).unwrap()),
        }
    }
}

#[derive(Debug)]
enum TestDirReader {
    Local(local::DirReader),
    Saved(std::vec::IntoIter<String>),
}

impl process_backend::DirReader for TestDirReader {
    fn read_next_name(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            Self::Local(reader) => process_backend::DirReader::read_next_name(reader, buf),
            Self::Saved(names) => match names.next() {
                Some(name) => {
                    if buf.len() < name.len() {
                        return Err(process_backend::Error::BufferTooSmall);
                    }
                    buf[..name.len()].copy_from_slice(name.as_bytes());
                    Ok(name.len())
                }
                None => Ok(0),
            },
        }
    }
}

impl Backend for TestBackend {
    type ProcessReader<'a> = <local::Backend as Backend>::ProcessReader<'a>;
    type FileReader<'a> = TestFileReader;
    type DirReader<'a> = TestDirReader;
    type MappedModuleMemoryReader<'a> = <local::Backend as Backend>::MappedModuleMemoryReader<'a>;

    fn pid(&self) -> Result<libc::pid_t> {
        Backend::pid(&self.local)
    }

    fn process_reader(&self) -> Self::ProcessReader<'_> {
        self.used.set(true);
        Backend::process_reader(&self.local)
    }

    fn stop_process(&self) -> Result<()> {
        if self.snapshot.is_some() {
            return Ok(());
        }
        Backend::stop_process(&self.local)
    }

    fn continue_process(&self) -> Result<()> {
        if self.snapshot.is_some() {
            return Ok(());
        }
        Backend::continue_process(&self.local)
    }

    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()> {
        if self.snapshot.is_some() {
            return Ok(());
        }
        Backend::suspend_thread(&self.local, tid)
    }

    fn resume_thread(&self, tid: libc::pid_t) -> Result<()> {
        if self.snapshot.is_some() {
            return Ok(());
        }
        Backend::resume_thread(&self.local, tid)
    }

    fn map_module_into_memory(
        &self,
        path: &CStr,
        offset: u64,
    ) -> Result<Self::MappedModuleMemoryReader<'_>> {
        Backend::map_module_into_memory(&self.local, path, offset)
    }

    fn stat_file(&self, path: &CStr) -> Result<process_backend::Stat> {
        Backend::stat_file(&self.local, path)
    }

    fn read_file(&self, path: &CStr) -> Result<Self::FileReader<'_>> {
        if let Some(snapshot) = &self.snapshot {
            let path = path.to_str().unwrap();
            if path == format!("/proc/{}/stat", self.local.pid()) {
                return Ok(TestFileReader::Saved(std::io::Cursor::new(
                    snapshot.stat.clone(),
                )));
            }
            if snapshot.vanished.iter().any(|tid| {
                path == format!("/proc/{tid}/status")
                    || path == format!("/proc/{}/task/{tid}/comm", self.local.pid())
            }) {
                return Err(process_backend::Error::Local(local::Error::OpenFileFailed(
                    libc::ENOENT,
                )));
            }
        }
        Backend::read_file(&self.local, path).map(TestFileReader::Local)
    }

    fn read_dir(&self, path: &CStr) -> Result<Self::DirReader<'_>> {
        if let Some(snapshot) = &self.snapshot
            && path.to_str().unwrap() == format!("/proc/{}/task", self.local.pid())
        {
            return Ok(TestDirReader::Saved(
                snapshot
                    .threads
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .into_iter(),
            ));
        }
        Backend::read_dir(&self.local, path).map(TestDirReader::Local)
    }

    fn read_link(&self, path: &CStr, buf: &mut [u8]) -> Result<usize> {
        Backend::read_link(&self.local, path, buf)
    }

    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs> {
        if self.deny_registers {
            return Err(process_backend::Error::Local(
                local::Error::GetRegistersFailed {
                    getregset_error: local::PtraceGetRegSetError::PtraceFailed(libc::EPERM),
                    legacy_error: local::PtraceGetRegsLegacyError::PtraceFailed(libc::EPERM),
                },
            ));
        }
        Backend::get_gen_regs(&self.local, tid)
    }

    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs> {
        if self.deny_registers {
            return Err(process_backend::Error::Local(
                local::Error::GetRegistersFailed {
                    getregset_error: local::PtraceGetRegSetError::PtraceFailed(libc::EPERM),
                    legacy_error: local::PtraceGetRegsLegacyError::PtraceFailed(libc::EPERM),
                },
            ));
        }
        Backend::get_fp_regs(&self.local, tid)
    }

    #[cfg(target_arch = "x86")]
    fn get_fpx_regs(&self, tid: libc::pid_t) -> Result<FpxRegs> {
        if self.deny_registers {
            return Err(process_backend::Error::Local(
                local::Error::GetRegistersFailed {
                    getregset_error: local::PtraceGetRegSetError::PtraceFailed(libc::EPERM),
                    legacy_error: local::PtraceGetRegsLegacyError::PtraceFailed(libc::EPERM),
                },
            ));
        }
        Backend::get_fpx_regs(&self.local, tid)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn ptrace_peekuser(&self, addr: usize) -> Result<[u8; process_backend::PTRACE_DATA_LEN]> {
        if self.deny_registers {
            return Err(process_backend::Error::Local(
                local::Error::GetRegistersFailed {
                    getregset_error: local::PtraceGetRegSetError::PtraceFailed(libc::EPERM),
                    legacy_error: local::PtraceGetRegsLegacyError::PtraceFailed(libc::EPERM),
                },
            ));
        }
        Backend::ptrace_peekuser(&self.local, addr)
    }

    fn force_process_reader_kind(
        &mut self,
        kind: process_backend::ProcessReaderKind,
    ) -> Result<()> {
        Backend::force_process_reader_kind(&mut self.local, kind)
    }

    fn fail_one_syscall_with(&self, errno: std::ffi::c_int) {
        Backend::fail_one_syscall_with(&self.local, errno)
    }
}

#[test]
fn custom_process_backend() {
    let mut child = common::start_child_and_wait_for_threads(3);
    let pid = child.id() as i32;
    let used = Rc::new(Cell::new(false));
    let mut config = MinidumpWriterConfig::new(pid, pid);
    config.set_process_backend(TestBackend {
        local: local::Backend::new(pid),
        used: used.clone(),
        deny_registers: false,
        snapshot: None,
    });
    let mut destination = std::io::Cursor::new(Vec::new());
    let result = config.write(&mut destination);
    child.kill().unwrap();
    child.wait().unwrap();

    let bytes = result.expect("could not write minidump");
    assert!(used.get());
    assert_eq!(bytes, destination.into_inner());
    let dump = Minidump::read(bytes).expect("could not read minidump");
    dump.get_stream::<MinidumpSystemInfo>().unwrap();
    let threads = dump.get_stream::<MinidumpThreadList>().unwrap();
    assert!(threads.threads.len() >= 3);
    assert!(
        threads
            .threads
            .iter()
            .all(|thread| thread.raw.thread_context.data_size > 0)
    );
}

#[test]
fn keep_all_threads_without_context() {
    let mut child = common::start_child_and_wait_for_threads(3);
    let pid = child.id() as i32;
    let expected: std::collections::HashSet<u32> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        })
        .collect();
    assert!(expected.len() >= 3);
    let mut config = MinidumpWriterConfig::new(pid, pid);
    config.set_process_backend(TestBackend {
        local: local::Backend::new(pid),
        used: Rc::new(Cell::new(false)),
        deny_registers: true,
        snapshot: None,
    });
    config.keep_threads_without_context();
    let result = config.write(&mut std::io::Cursor::new(Vec::new()));
    child.kill().unwrap();
    child.wait().unwrap();

    let dump = Minidump::read(result.expect("could not write minidump")).unwrap();
    let threads = dump.get_stream::<MinidumpThreadList>().unwrap();
    let actual: std::collections::HashSet<_> = threads
        .threads
        .iter()
        .map(|thread| thread.raw.thread_id)
        .collect();
    assert_eq!(actual, expected);
    for thread in &threads.threads {
        assert_eq!(thread.raw.thread_context.data_size, 0);
        assert_eq!(thread.raw.thread_context.rva, 0);
        assert_eq!(thread.raw.stack.start_of_memory_range, 0);
        assert_eq!(thread.raw.stack.memory.data_size, 0);
        assert_eq!(thread.raw.stack.memory.rva, 0);
    }
    let errors = common::read_minidump_soft_errors_or_panic(&dump);
    let mut register_failures = 0;
    common::visit_json_objects(&errors, &mut Vec::new(), &mut |_, value| {
        if value == "GetGenRegsFailed" {
            register_failures += 1;
        }
    });
    assert_eq!(register_failures, expected.len());
}

#[test]
fn missing_registers_default_behavior() {
    let mut child = common::start_child_and_wait_for_threads(3);
    let pid = child.id() as i32;
    let mut config = MinidumpWriterConfig::new(pid, pid);
    config.set_process_backend(TestBackend {
        local: local::Backend::new(pid),
        used: Rc::new(Cell::new(false)),
        deny_registers: true,
        snapshot: None,
    });
    let result = config.write(&mut std::io::Cursor::new(Vec::new()));
    child.kill().unwrap();
    child.wait().unwrap();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let dump = Minidump::read(result.expect("could not write minidump")).unwrap();
        let threads = dump.get_stream::<MinidumpThreadList>().unwrap();
        assert!(threads.threads.is_empty());
        common::assert_minidump_contains_soft_error(&dump, "DetachSkippedThread");
    }
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    assert!(result.is_err());
}

#[test]
fn snapshot_backend_keeps_vanished_threads() {
    let mut child = common::start_child_and_wait_for_threads(3);
    let pid = child.id() as i32;
    let live: std::collections::BTreeMap<i32, String> =
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .map(|entry| {
                let tid = entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                let name = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/comm")).unwrap();
                (tid, name.trim_end().to_owned())
            })
            .collect();
    let vanished: Vec<i32> = (0..2)
        .map(|_| {
            let mut exited = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--list")
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let tid = exited.id() as i32;
            assert!(exited.wait().unwrap().success());
            assert!(!std::path::Path::new(&format!("/proc/{tid}")).exists());
            tid
        })
        .collect();
    let mut saved = vec![vanished[0]];
    for (index, tid) in live.keys().enumerate() {
        saved.push(*tid);
        if index == 0 {
            saved.push(vanished[1]);
        }
    }
    let expected: std::collections::HashSet<_> = saved.iter().map(|tid| *tid as u32).collect();
    let mut stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let state_offset = stat.rfind(')').unwrap() + 2;
    stat.replace_range(state_offset..state_offset + 1, "T");
    let mut config = MinidumpWriterConfig::new(pid, pid);
    config.set_process_backend(TestBackend {
        local: local::Backend::new(pid),
        used: Rc::new(Cell::new(false)),
        deny_registers: true,
        snapshot: Some(Snapshot {
            threads: saved,
            vanished: vanished.clone(),
            stat: stat.into_bytes(),
        }),
    });
    config.keep_threads_without_context();
    let result = config.write(&mut std::io::Cursor::new(Vec::new()));
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert_ne!(stat.as_bytes()[stat.rfind(')').unwrap() + 2], b'T');

    let dump = Minidump::read(result.expect("could not write snapshot minidump")).unwrap();
    let threads = dump.get_stream::<MinidumpThreadList>().unwrap();
    let actual: std::collections::HashSet<_> = threads
        .threads
        .iter()
        .map(|thread| thread.raw.thread_id)
        .collect();
    assert_eq!(actual, expected);
    for thread in &threads.threads {
        assert_eq!(thread.raw.thread_context.data_size, 0);
        assert_eq!(thread.raw.thread_context.rva, 0);
        assert_eq!(thread.raw.stack.start_of_memory_range, 0);
        assert_eq!(thread.raw.stack.memory.data_size, 0);
        assert_eq!(thread.raw.stack.memory.rva, 0);
    }
    let names = dump.get_stream::<MinidumpThreadNames>().unwrap();
    for (tid, name) in &live {
        assert_eq!(names.get_name(*tid as u32).as_deref(), Some(name.as_str()));
    }
    for tid in &vanished {
        assert!(names.get_name(*tid as u32).is_none());
    }
    let exception = dump.get_stream::<MinidumpException>().unwrap();
    assert_eq!(exception.thread_id, pid as u32);
    assert_eq!(exception.raw.thread_context.data_size, 0);
    assert_eq!(exception.raw.thread_context.rva, 0);
    assert_eq!(exception.raw.exception_record.exception_address, 0);
    assert_eq!(
        exception.raw.exception_record.exception_code,
        minidump_common::errors::ExceptionCodeLinux::DUMP_REQUESTED as u32
    );
    let memory = dump.get_stream::<MinidumpMemoryList>().unwrap();
    assert_eq!(memory.iter().count(), 0);

    let errors = common::read_minidump_soft_errors_or_panic(&dump);
    let (mut registers, mut status, mut names, mut stop) = (0, 0, 0, 0);
    common::visit_json_objects(&errors, &mut Vec::new(), &mut |path, value| {
        if value == "GetGenRegsFailed" {
            registers += 1;
        }
        if value == "ReadFileFailed" && path.iter().any(|name| name == "ThreadInfoError") {
            status += 1;
        }
        if value == "ReadThreadNameFailed" {
            names += 1;
        }
        if value == "StopProcessFailed" {
            stop += 1;
        }
    });
    assert_eq!(registers, live.len());
    assert_eq!(status, vanished.len());
    assert_eq!(names, vanished.len());
    assert_eq!(stop, 0);
}
