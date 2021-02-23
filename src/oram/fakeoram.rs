use std::collections::HashMap;
use std::path::Path;

use bytes::{Buf, Bytes};
use log::debug;

use crate::io::BaseIOService;
use crate::oram::BaseORAM;
use crate::ORAMConfig;

/// Implementation of a fake ORAM scheme
///
/// This is a very simple ORAM scheme which serves as an example.
/// It can be thought as a "hello world" of ORAM schemes.
/// Note that this does not actually preserve privacy because it does not
/// scramble access patterns and does not perform any encryption.
pub struct FakeORAM<'a> {
    pub args: &'a ORAMConfig,
    pub position_map: HashMap<i64, i64>,
    pub io: Box<dyn BaseIOService + 'a>,
}

impl BaseORAM for FakeORAM<'_> {
    fn init(&mut self) {
        debug!("Init FakeORAM...");
        self.init_public_storage();
    }

    /// Read the specified block from ORAM
    ///
    /// This is simply achieved by reading at the right offset
    /// within the file containing the desired block.
    /// The position map tells us which file contains the specified block.
    fn read(&mut self, block_id: i64) -> Vec<u8> {
        let bucket_id = self
            .position_map
            .get(&block_id)
            .unwrap_or_else(|| panic!("No such block ID in position map: {}", block_id));
        self.read_block(bucket_id, block_id)
    }

    /// Write the `data` to the specified block in the ORAM
    ///
    /// This is simply achieved by writing at the right offset
    /// within the file that contains the target block.
    /// The position map tells us which file contains the target block.
    fn write(&mut self, block_id: i64, data: Bytes) -> usize {
        let bucket_id = *self
            .position_map
            .get(&block_id)
            .expect("No such block ID in position map");
        self.write_block(&bucket_id, block_id, data)
    }

    fn size(&self) -> i64 {
        let args = self.args;
        args.b * args.z * args.n
    }

    fn name(&self) -> String {
        String::from("fakeoram")
    }

    fn args(&self) -> &ORAMConfig {
        self.args
    }
}

impl<'a> FakeORAM<'a> {
    pub fn new(args: &'a ORAMConfig, io: Box<dyn BaseIOService + 'a>) -> Self {
        let position_map = FakeORAM::init_position_map(args);
        Self {
            args,
            position_map,
            io,
        }
    }

    /// Initialize a simple position map.
    ///
    /// Each block is simply mapped to a file.
    /// Each file contains `z` blocks, simply appended.
    fn init_position_map(args: &'a ORAMConfig) -> HashMap<i64, i64> {
        let mut map = HashMap::new();
        let blocks_count = args.n * args.z;
        for i in 0..blocks_count {
            let block_id = i;
            let leaf_id = i / args.z;
            map.insert(block_id, leaf_id);
        }
        map
    }

    fn init_public_storage(&mut self) {
        debug!("Init public storage...");

        let bucket_size = self.args.z * self.args.b;
        let zeros = vec![0u8; bucket_size as usize];

        for i in 0..self.args.n {
            let node_path = self.node_path(i);
            debug!("init node {}/{} : {} ", i + 1, self.args.n, node_path);

            self.io.write_file(node_path, zeros.as_slice());
        }

        debug!("...Done!");
    }

    fn node_path(&self, i: i64) -> String {
        let filename = format!("node_{}.oram", i);
        let path = Path::new(&self.args.public_directory);
        let node_path = path.join(filename);
        String::from(node_path.to_str().unwrap())
    }

    pub fn read_block(&self, bucket_id: &i64, block_id: i64) -> Vec<u8> {
        let node_file = self.node_path(*bucket_id);
        let block_id_within_bucket = block_id % self.args.z;
        let offset = (block_id_within_bucket * self.args.b) as u64;
        let length = self.args.b as u64;

        self.io.read_from_file(node_file, offset, length)
    }

    pub fn write_block(&mut self, bucket_id: &i64, block_id: i64, data: Bytes) -> usize {
        let node_file = self.node_path(*bucket_id);
        let block_id_within_bucket = block_id % self.args.z;
        let offset = (block_id_within_bucket * self.args.b) as u64;

        self.io.write_to_file(node_file, offset, data.bytes())
    }
}
