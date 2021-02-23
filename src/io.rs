use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::ORAMConfig;

/// Base trait for an IO service
pub trait BaseIOService: Send {
    /// Read `length` bytes from file at `path` starting at byte `offset`
    fn read_from_file(&self, path: String, offset: u64, length: u64) -> Vec<u8>;

    /// Write bytes in `buf` to file at `path` starting at byte `offset`
    ///
    ///# Invariants
    /// The file must already exist. For example, create it first using write_file().
    fn write_to_file(&mut self, path: String, offset: u64, buf: &[u8]) -> usize;

    /// Write bytes in `buf` to file at `path`
    fn write_file(&mut self, path: String, buf: &[u8]) -> usize;

    /// Read file contents
    fn read_file(&self, path: String) -> Vec<u8>;
}

/// Disk IO Service
///
/// This IO service reads and write data from a local disk.
pub struct DiskIOService;

impl BaseIOService for DiskIOService {
    fn read_from_file(&self, path: String, offset: u64, length: u64) -> Vec<u8> {
        let mut file = fs::File::open(path).expect("Cannot open file");
        file.seek(SeekFrom::Start(offset))
            .expect("Cannot seek to offset");
        let mut bytes_read = Vec::new();
        let mut limited = file.take(length);
        limited
            .read_to_end(&mut bytes_read)
            .expect("Failed to read bytes");
        bytes_read
    }

    fn write_to_file(&mut self, path: String, offset: u64, buf: &[u8]) -> usize {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("Cannot open file in write mode");
        file.seek(SeekFrom::Start(offset))
            .expect("Cannot seek to offset");

        file.write(buf).expect("Failed to write bytes")
    }

    fn write_file(&mut self, path: String, buf: &[u8]) -> usize {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.clone())
            .unwrap_or_else(|_| panic!("Cannot open file in write mode: {}", path));

        file.write(buf).expect("Failed to write bytes")
    }

    fn read_file(&self, path: String) -> Vec<u8> {
        let mut file =
            fs::File::open(path.clone()).unwrap_or_else(|_| panic!("Cannot open file: {}", path));
        let mut bytes_read = Vec::new();
        file.read_to_end(&mut bytes_read)
            .expect("Failed to read bytes");
        bytes_read
    }
}

impl DiskIOService {
    pub fn new() -> Self {
        Self {}
    }
}

/// Memory IO Service
///
/// This IO service reads and writes data from memory.
/// It is therefore faster than DiskIOService, however, it is not persistent.
/// Hence, it should only be used for testing purposes.
pub struct MemoryIOService {
    memory: HashMap<String, Vec<u8>>,
}

impl BaseIOService for MemoryIOService {
    fn read_from_file(&self, path: String, offset: u64, length: u64) -> Vec<u8> {
        let bytes = self.memory.get(&path).expect("No such file in memory");
        let bytes_read = &bytes[(offset as usize)..((offset + length) as usize)];
        bytes_read.to_vec()
    }

    fn write_to_file(&mut self, path: String, offset: u64, buf: &[u8]) -> usize {
        let bytes = self.memory.get_mut(&path).expect("No such file in memory");
        bytes.splice(
            (offset as usize)..((offset as usize + buf.len()) as usize),
            buf[..].iter().cloned(),
        );
        buf.len()
    }

    fn write_file(&mut self, path: String, buf: &[u8]) -> usize {
        self.memory.insert(path, buf.to_vec());
        buf.len()
    }

    fn read_file(&self, path: String) -> Vec<u8> {
        let bytes = self
            .memory
            .get(&path)
            .unwrap_or_else(|| panic!("No such file in memory {}", path));
        bytes.to_vec()
    }
}

impl MemoryIOService {
    pub fn new() -> Self {
        Self {
            memory: HashMap::new(),
        }
    }
}

/// Return the IO service corresponding to the name given in parameter.
pub fn get_io<'a>(args: &'a ORAMConfig) -> Box<dyn BaseIOService + 'a> {
    match &args.io[..] {
        "disk" => Box::new(DiskIOService::new()) as Box<dyn BaseIOService + 'a>,
        "memory" => Box::new(MemoryIOService::new()) as Box<dyn BaseIOService + 'a>,
        _ => Box::new(DiskIOService::new()) as Box<dyn BaseIOService + 'a>,
    }
}
