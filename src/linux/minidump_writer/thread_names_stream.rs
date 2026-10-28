use super::*;

#[derive(Debug, Error, serde::Serialize)]
pub enum SectionThreadNamesError {
    #[error("Failed integer conversion")]
    TryFromIntError(
        #[from]
        #[serde(skip)]
        std::num::TryFromIntError,
    ),
    #[error("Failed to write to memory")]
    MemoryWriterError(#[from] MemoryWriterError),
    #[error("Failed to write to memory buffer")]
    IOError(
        #[from]
        #[serde(serialize_with = "serialize_io_error")]
        std::io::Error,
    ),
}

impl MinidumpWriter {
    pub fn write_thread_names_stream(
        &self,
        buffer: &mut DumpBuf,
    ) -> Result<MDRawDirectory, SectionThreadNamesError> {
        // Only count threads that have a name
        let num_threads = self.threads.iter().filter(|t| t.name.is_some()).count();
        // Memory looks like this:
        // <num_threads><thread_1><thread_2>...

        let list_header = MemoryWriter::<u32>::alloc_with_val(buffer, num_threads as u32)?;

        let mut dirent = MDRawDirectory {
            stream_type: MDStreamType::ThreadNamesStream as u32,
            location: list_header.location(),
        };

        let mut thread_list =
            MemoryArrayWriter::<MDRawThreadName>::alloc_array(buffer, num_threads)?;
        dirent.location.data_size += thread_list.location().data_size;

        for (idx, item) in self
            .threads
            .iter()
            .filter(|thread| thread.name.is_some())
            .enumerate()
        {
            if let Some(name) = &item.name {
                let pos = write_string_to_location(buffer, name)?;
                let thread = MDRawThreadName {
                    thread_id: item.tid.try_into()?,
                    thread_name_rva: pos.rva.into(),
                };
                thread_list.set_value_at(buffer, thread, idx)?;
            }
        }
        Ok(dirent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minidump::{MinidumpStream, MinidumpThreadNames};

    #[test]
    fn interleaved_missing_thread_names() {
        for gap in [1, 32] {
            let mut writer = MinidumpWriterConfig::new(std::process::id() as Pid, 0).build();
            let names = std::iter::once(None)
                .chain(std::iter::once(Some("a")))
                .chain(std::iter::repeat_n(None, gap))
                .chain(std::iter::once(Some("b")));
            writer.threads = names
                .enumerate()
                .map(|(index, name)| Thread {
                    tid: (index + 1) as Pid,
                    name: name.map(str::to_owned),
                })
                .collect();
            let mut buffer = Buffer::with_capacity(0);
            let directory = writer.write_thread_names_stream(&mut buffer).unwrap();
            let start = directory.location.rva as usize;
            let end = start + directory.location.data_size as usize;
            assert_eq!(
                u32::from_le_bytes(buffer[start..start + 4].try_into().unwrap()),
                2
            );
            let parsed = MinidumpThreadNames::read(
                &buffer[start..end],
                &buffer,
                scroll::Endian::Little,
                None,
            )
            .unwrap();
            for thread in &writer.threads {
                assert_eq!(
                    parsed.get_name(thread.tid as u32).as_deref(),
                    thread.name.as_deref()
                );
            }
        }
    }
}
