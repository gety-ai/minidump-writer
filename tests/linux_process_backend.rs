#![cfg(any(target_os = "linux", target_os = "android"))]

use minidump::{Minidump, MinidumpSystemInfo, MinidumpThreadList};
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
}

impl Backend for TestBackend {
    type ProcessReader<'a> = <local::Backend as Backend>::ProcessReader<'a>;
    type FileReader<'a> = <local::Backend as Backend>::FileReader<'a>;
    type DirReader<'a> = <local::Backend as Backend>::DirReader<'a>;
    type MappedModuleMemoryReader<'a> = <local::Backend as Backend>::MappedModuleMemoryReader<'a>;

    fn pid(&self) -> Result<libc::pid_t> {
        Backend::pid(&self.local)
    }

    fn process_reader(&self) -> Self::ProcessReader<'_> {
        self.used.set(true);
        Backend::process_reader(&self.local)
    }

    fn stop_process(&self) -> Result<()> {
        Backend::stop_process(&self.local)
    }

    fn continue_process(&self) -> Result<()> {
        Backend::continue_process(&self.local)
    }

    fn suspend_thread(&self, tid: libc::pid_t) -> Result<()> {
        Backend::suspend_thread(&self.local, tid)
    }

    fn resume_thread(&self, tid: libc::pid_t) -> Result<()> {
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
        Backend::read_file(&self.local, path)
    }

    fn read_dir(&self, path: &CStr) -> Result<Self::DirReader<'_>> {
        Backend::read_dir(&self.local, path)
    }

    fn read_link(&self, path: &CStr, buf: &mut [u8]) -> Result<usize> {
        Backend::read_link(&self.local, path, buf)
    }

    fn get_gen_regs(&self, tid: libc::pid_t) -> Result<GenRegs> {
        Backend::get_gen_regs(&self.local, tid)
    }

    fn get_fp_regs(&self, tid: libc::pid_t) -> Result<FpRegs> {
        Backend::get_fp_regs(&self.local, tid)
    }

    #[cfg(target_arch = "x86")]
    fn get_fpx_regs(&self, tid: libc::pid_t) -> Result<FpxRegs> {
        Backend::get_fpx_regs(&self.local, tid)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn ptrace_peekuser(&self, addr: usize) -> Result<[u8; process_backend::PTRACE_DATA_LEN]> {
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
