use std::cmp::min;
use std::path::Path;

use bytes::Bytes;

use fakeoram::FakeORAM;
use pathoram::PathORAM;

use crate::io::BaseIOService;
use crate::{get_io, ORAMConfig};

pub mod fakeoram;
pub mod pathoram;

/// Base trait for an ORAM scheme
pub trait BaseORAM: Send {
    fn test_state(&mut self) -> bool {
        true
    }

    /// Initialize the ORAM
    fn init(&mut self) {}

    /// Cleanup the ORAM
    fn cleanup(&mut self) {}

    /// Called after each read or write operation
    fn post_op(&mut self) {}

    /// Read block with id `block_id` and return the bytes read
    fn read(&mut self, block_id: i64) -> Vec<u8>;

    /// Write bytes in `data` inside of block with id `block_id`.
    /// Return the number of bytes written.
    fn write(&mut self, block_id: i64, data: Bytes) -> usize;

    /// Return the total size of the ORAM
    fn size(&self) -> i64;

    /// Return the oram's name
    fn name(&self) -> String;

    /// Return the CLI arguments
    fn args(&self) -> &ORAMConfig;

    /// Return the filename of the node with given number
    fn node_filename(&self, i: i64) -> String {
        format!("node_{}.oram", i)
    }

    /// Return the path to the node with given number
    fn node_path(&self, i: i64) -> String {
        let filename = self.node_filename(i);
        let path = Path::new(&self.args().public_directory);
        let node_path = path.join(filename);
        String::from(node_path.to_str().unwrap())
    }
}

/// ORAMFS holds the ORAM, and some parameters
pub struct ORAMFS<'a> {
    pub args: &'a ORAMConfig,
    pub oram_size: u64,
    pub oram: Box<dyn BaseORAM + 'a>,
}

impl<'a> ORAMFS<'a> {
    /// Create a new ORAMFS
    pub fn new(args: &'a ORAMConfig) -> Self {
        let io = get_io(&args);

        let oram_size = (args.n * args.z * args.b) as u64;
        let mut oram = get_oram(args, io);

        if args.init {
            oram.init();
        }

        Self {
            args,
            oram_size,
            oram,
        }
    }

    /// Compute practical parameters for a given ORAM size
    pub fn params_for_size(oram_size: i64) -> (i64, i64, i64) {
        let mut n = 255;
        let mut b = 16384;
        let mut z = 4;
        let mut i = 0;

        // allow for ORAMs as small as 1 MB
        if oram_size < 16000000 {
            n = 127;
            b = 4096;
            z = 4;
        }

        while n * b * z < oram_size {
            if i % 3 == 0 {
                z += 1;
            } else if i % 3 == 1 {
                n = (n * 2) + 1;
            } else if i % 3 == 2 {
                b *= 4;
            }
            i += 1;
        }
        (n, z, b)
    }

    /// Cleanup the ORAM
    pub fn cleanup(&mut self) {
        self.oram.cleanup();
    }

    /// Read `length` bytes starting at offset `offset`.
    ///
    /// Split larger reads into smaller reads of length equal
    /// to the ORAM block size, and reassemble the bytes read
    /// with the multiple smaller read operations before returning.
    /// Return the bytes read.
    pub fn split_read(&mut self, length: u32, offset: i64) -> Vec<u8> {
        let mut block_id: i64 = 0;
        let mut offset_copy = offset;

        while offset_copy >= self.args.b {
            block_id += 1;
            offset_copy -= self.args.b;
        }

        // split operation into multiple smaller operations on single blocks
        let mut length_copy = length as i64;
        let mut all_bytes: Vec<u8> = Vec::new();
        let blocks_count = self.args.z * self.args.n;

        while length_copy > 0 && block_id < blocks_count {
            let block_bytes = self.oram.read(block_id);
            let end = min(offset_copy + length_copy, self.args.b);
            let bytes_to_add = &block_bytes[(offset_copy as usize)..(end as usize)];
            all_bytes.append(&mut bytes_to_add.to_vec());
            length_copy -= bytes_to_add.len() as i64;
            offset_copy = 0;
            block_id += 1;
        }

        all_bytes
    }

    /// Write `data` bytes starting at offset `offset`.
    ///
    /// Split larger writes into smaller writes of length equal
    /// to the ORAM block size.
    /// Return the number of bytes written.
    pub fn split_write(&mut self, offset: i64, mut data: &[u8]) -> u32 {
        let mut block_id: i64 = 0;
        let mut offset_copy = offset;

        while offset_copy >= self.args.b {
            block_id += 1;
            offset_copy -= self.args.b;
        }

        // split operation into multiple smaller operations in single blocks
        let mut length_copy = data.len() as i64;
        let mut total_bytes_written = 0i64;
        let blocks_count = self.args.z * self.args.n;

        while length_copy > 0 && block_id < blocks_count {
            let end = min(offset_copy + length_copy, self.args.b);
            let length_to_write = end - offset_copy;

            let block_bytes: &[u8];
            let mut oram_bytes: Vec<u8>;
            // read block first and replace part of it if needed
            if offset_copy > 0 || length_to_write < self.args.b {
                // must first read block and overwrite part of it if offset is non-zero
                oram_bytes = self.oram.read(block_id);
                // block_bytes[offset_copy..end] = data[0..length_to_write]
                oram_bytes.splice(
                    (offset_copy as usize)..(end as usize),
                    data[0..(length_to_write as usize)].iter().cloned(),
                );
                block_bytes = &oram_bytes[..];
            } else {
                block_bytes = &data[..(self.args.b as usize)];
            }

            data = &data[(length_to_write as usize)..];

            let _ = self.oram.write(block_id, Bytes::from(block_bytes.to_vec()));

            total_bytes_written += length_to_write;
            length_copy -= length_to_write;
            offset_copy = 0;
            block_id += 1;
        }

        total_bytes_written as u32
    }
}

/// Return the ORAM corresponding to the name given in parameter.
pub fn get_oram<'a>(
    args: &'a ORAMConfig,
    io: Box<dyn BaseIOService + 'a>,
) -> Box<dyn BaseORAM + 'a> {
    match &args.algorithm[..] {
        "fakeoram" => Box::new(FakeORAM::new(args, io)) as Box<dyn BaseORAM + 'a>,
        "pathoram" => Box::new(PathORAM::new(args, io)) as Box<dyn BaseORAM + 'a>,
        _ => Box::new(FakeORAM::new(args, io)) as Box<dyn BaseORAM + 'a>,
    }
}

#[cfg(test)]
mod tests {
    use crate::ORAMFS;

    #[test]
    pub fn test_params_for_size() {
        let oram_size = 1_000_000_000;
        let (n, z, b) = ORAMFS::params_for_size(oram_size);
        assert_eq!((n, z, b), (1023, 6, 262144))
    }
}
