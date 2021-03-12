use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use std::path::Path;

use aes_ctr::Aes128Ctr;
use aes_ctr::cipher::stream::generic_array::GenericArray;
use bytes::{Buf, Bytes, BytesMut};
use chacha20::{ChaCha8, Key, Nonce};
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use log::{debug, info};
use nohash_hasher::NoHashHasher;
use rand::{AsByteSliceMut, Rng, thread_rng};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

use crate::io::BaseIOService;
use crate::oram::BaseORAM;
use crate::oram::pathoram::tree::TreeNode;
use crate::ORAMConfig;

pub mod tree;

#[derive(Clone, Serialize, Deserialize)]
pub struct Block {
    id: i64,
    payload: Bytes,
}

#[derive(Serialize, Deserialize)]
pub struct Bucket {
    version: String,
    format: String,
    blocks: Vec<Block>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedBytes {
    iv: Bytes,
    ciphertext: BytesMut,
}

/// An implementation of the Path ORAM scheme.
///
/// The Path ORAM paper is available at https://eprint.iacr.org/2013/280.pdf
pub struct PathORAM<'a> {
    pub args: &'a ORAMConfig,
    pub io: Box<dyn BaseIOService + 'a>,
    pub position_map: HashMap<i64, i64, BuildHasherDefault<NoHashHasher<i64>>>,
    pub stash: Vec<Block>,
    pub tree: TreeNode,
    pub encryption_key: Vec<u8>,
}

impl BaseORAM for PathORAM<'_> {
    fn test_state(&mut self) -> bool {
        self.verify_main_invariant()
    }

    fn init(&mut self) {
        self.setup();
    }

    fn cleanup(&mut self) {
        debug!("Path ORAM cleanup...");
        self.save();
        debug!("...done!");
    }

    /// Delegate read operations to the access() method of Path ORAM
    fn read(&mut self, block_id: i64) -> Vec<u8> {
        let read_bytes = self.access("read", block_id, None);
        match read_bytes {
            Some(bytes) => bytes.to_vec(),
            None => panic!("Could not read block"),
        }
    }

    /// Delegate write operations to the access() method of Path ORAM
    fn write(&mut self, block_id: i64, data: Bytes) -> usize {
        let _ = self.access("write", block_id, Some(data.clone()));
        data.len()
    }

    fn size(&self) -> i64 {
        self.args.b * self.args.z * self.args.n
    }

    fn name(&self) -> String {
        String::from("pathoram")
    }

    fn args(&self) -> &ORAMConfig {
        self.args
    }

    /// Save the stash and position map after each operation.
    /// This should prevent data loss in case the process is killed before unmounting.
    fn post_op(&mut self) {
        self.save();
    }
}

impl<'a> PathORAM<'a> {
    pub fn new(args: &'a ORAMConfig, io: Box<dyn BaseIOService + 'a>) -> Self {
        let mut pathoram = Self {
            args,
            io,
            position_map: HashMap::<i64, i64, BuildHasherDefault<NoHashHasher<i64>>>::default(),
            tree: TreeNode::create_tree(args.n),
            stash: Vec::new(),
            encryption_key: Vec::new(),
        };

        if !args.init {
            pathoram.load();
        }

        pathoram
    }

    /// Initialize the ORAM
    pub fn setup(&mut self) {
        info!("Initializing Path ORAM...");
        self.load_encryption_key();
        let rbmap = self.init_position_map();
        self.init_public_storage(rbmap);
        info!("...initialization complete!")
    }

    /// Verify that each block is correctly mapped to a leaf
    pub fn verify_main_invariant(&mut self) -> bool {
        let mut incorrectly_mapped_blocks = vec![];

        for bucket_id in 0..self.args.n {
            let bucket = self.read_bucket(bucket_id);
            for block in bucket {
                if block.id != -1 {
                    let leaf = self.position_map.get(&block.id).unwrap();
                    let path = self.tree.path(*leaf);
                    if !path.contains(&bucket_id) {
                        incorrectly_mapped_blocks.push(block.id);
                    }
                }
            }
        }
        incorrectly_mapped_blocks.is_empty()
    }

    /// The Path ORAM Access function.
    /// Do operation `op` ("read" or "write") on block with ID `a`.
    /// If it is a "write", replace data with `data_star`.
    /// Return the block's data, if op == "read".
    /// Return the block's previous data if op == "write".
    pub fn access(&mut self, op: &str, a: i64, data_star: Option<Bytes>) -> Option<Bytes> {
        let x = *self.position_map.get(&a).unwrap();
        let tree_height = self.tree.height;

        let max_leaf = 2i64.pow(tree_height as u32) - 1;
        let mut rng = thread_rng();
        let new_random_leaf = rng.gen_range(0, max_leaf + 1);
        self.position_map.insert(a, new_random_leaf);
        for l in 0..tree_height + 1 {
            // S <- S  U ReadBucket(P(x, l))
            let bucket_id = self.tree.pathl(x, l);
            let mut blocks: Vec<Block> = self.read_bucket(bucket_id);
            blocks.retain(|b| b.id != -1);

            self.stash.extend(blocks);
        }

        // data <- Read block a from S
        let mut data = None;
        for b in &self.stash {
            if b.id == a {
                data = Some(b.payload.clone());
            }
        }
        if data.is_none() {
            panic!(format!("Failed to find block {} in stash", { a }));
        }

        // give priority to block a in stash (put it at the front)
        self.stash.retain(|b| b.id != a);
        self.stash.insert(
            0,
            Block {
                id: a,
                payload: data.clone().unwrap(),
            },
        );

        if op == "write" {
            // S <- (S - {(a, data)}) U {(a, data*)}
            self.stash.retain(|b| b.id != a);
            self.stash.insert(
                0,
                Block {
                    id: a,
                    payload: data_star.unwrap(),
                },
            );
        }

        for l in (0..tree_height + 1).rev() {
            let pxl = self.tree.pathl(x, l);

            // S' <- {(a', data') in S: P(x, l) == P(position[a'], l)}
            let mut s_prime: Vec<Block> = self.stash.clone();
            s_prime.retain(|b| {
                let leaf = *self.position_map.get(&b.id).unwrap();
                pxl == self.tree.pathl(leaf, l)
            });

            let select_count = min(s_prime.len(), self.args.z as usize);
            s_prime = s_prime[0..select_count].to_vec();

            // S <- S - S'
            let s_prime_block_ids: HashSet<i64, BuildHasherDefault<NoHashHasher<i64>>> =
                s_prime.iter().map(|b| b.id).collect();
            self.stash.retain(|b| !s_prime_block_ids.contains(&b.id));

            // WriteBucket(P(x, l), S')
            self.write_bucket(pxl, s_prime);
        }

        data
    }

    /// Return the path to the file containing the stash
    /// in the client data directory.
    pub fn stash_path(&self) -> String {
        String::from(
            Path::new(&self.args.client_data_dir)
                .join("stash.bin")
                .to_str()
                .unwrap(),
        )
    }

    /// Return the path to the file containing the position map
    /// in the client data directory.
    pub fn position_map_path(&self) -> String {
        String::from(
            Path::new(&self.args.client_data_dir)
                .join("position_map.bin")
                .to_str()
                .unwrap(),
        )
    }

    /// Load the encryption key
    ///
    /// Unless encryption is disabled, this loads the encryption key.
    /// This is achieved, either by reading it from the specified file,
    /// or by deriving it from the given passphrase.
    /// If a passphrase was supplied, the derived key is automatically
    /// stretched to the appropriate size for the selected cipher.
    pub fn load_encryption_key(&mut self) {
        if !self.args.disable_encryption {
            if self.args.encryption_passphrase.is_empty() {
                debug!("Loading encryption key from file...");
                self.encryption_key = self.io.read_file(self.args.encryption_key_file.clone());
            } else {
                debug!("Deriving encryption key from supplied passphrase...");
                let context = "PATHORAM encryption key";
                let key_size = match &self.args.cipher[..] {
                    "aes-ctr" => 16,
                    "aes-ctr-openssl" => 16,
                    _ => 32, // ChaCha8
                };
                let mut derived_key = vec![0; key_size];
                blake3::derive_key(
                    context,
                    self.args.encryption_passphrase.as_bytes(),
                    &mut derived_key,
                );
                self.encryption_key = derived_key;
            }
        }
    }

    /// Load the client data
    pub fn load(&mut self) {
        debug!("Loading client data from disk...");
        self.load_encryption_key();

        let stash_bytes = self.io.read_file(self.stash_path());
        self.stash = bincode::deserialize(&stash_bytes).unwrap();

        let position_map_bytes = self.io.read_file(self.position_map_path());
        self.position_map = bincode::deserialize(&position_map_bytes).unwrap();

        debug!("...done!");
    }

    /// Save the client data
    pub fn save(&mut self) {
        debug!("Saving client data to disk...");
        // create client data dir if it doesn't exist
        match std::fs::create_dir_all(Path::new(&self.args.client_data_dir)) {
            Ok(_) => (),
            Err(e) => panic!("Failed to create client directory: {}", e),
        }

        // save stash and position map
        let stash_bytes = bincode::serialize(&self.stash).unwrap();
        let position_map_bytes = bincode::serialize(&self.position_map).unwrap();
        self.io.write_file(self.stash_path(), &stash_bytes);
        self.io
            .write_file(self.position_map_path(), &position_map_bytes);
        debug!("...done!");
    }

    /// Initialize the position map with random values.
    /// Each block is assigned to a random xth leaf in the tree, where x in 0..leaves_count
    pub fn init_position_map(&mut self) -> HashMap<i64, HashMap<i64, i64>> {
        let block_count = self.args.n * self.args.z;
        let mut block_ids: Vec<i64> = (0..block_count).collect();
        block_ids.shuffle(&mut thread_rng());

        let mut bmap = HashMap::new(); // block_id -> (bucket_id, block_index_within_bucket)
        let mut rbmap: HashMap<i64, HashMap<i64, i64>> = HashMap::new(); // bucket_id -> block_index_within_bucket -> block_id

        let mut i = 0;
        for bucket_id in 0..self.args.n {
            for block_index in 0..self.args.z {
                let block_id = block_ids.get(i).unwrap();
                bmap.insert(*block_id, (bucket_id, block_index));

                // rbmap.put(bucket_id, block_index, block_id)
                Self::mapmap_insert(&mut rbmap, &bucket_id, block_index, block_id);
                i += 1;
            }
        }

        // compute leaf number for each block
        let leaves_count = self.tree.leaves_count;

        // find random leaf under bucket
        let mut leaves: Vec<i64> = (0..leaves_count).collect();
        leaves.shuffle(&mut thread_rng());

        for block_id in 0..block_count {
            let (bucket_id, _) = bmap.get(&block_id).unwrap();

            let mut found_leaf = None;
            for x in &leaves {
                if found_leaf.is_some() {
                    break;
                }
                let p = self.tree.path(*x);
                if p.contains(bucket_id) {
                    found_leaf = Some(*x);
                }
            }

            self.position_map.insert(block_id, found_leaf.unwrap());
        }

        rbmap
    }

    pub fn mapmap_insert(
        rbmap: &mut HashMap<i64, HashMap<i64, i64>>,
        bucket_id: &i64,
        block_index: i64,
        block_id: &i64,
    ) {
        match rbmap.get_mut(&bucket_id) {
            Some(entry) => {
                entry.insert(block_index, *block_id);
            }
            _ => {
                let mut new_map = HashMap::new();
                new_map.insert(block_index, *block_id);
                rbmap.insert(*bucket_id, new_map);
            }
        }
    }

    /// Initialize the public storage
    ///
    /// This creates one file per bucket in the tree.
    /// Each file is filled with zeros so that the file size matches the bucket size.
    pub fn init_public_storage(&mut self, rbmap: HashMap<i64, HashMap<i64, i64>>) {
        debug!("Initializing public storage...");
        for (bucket_id, y) in rbmap {
            let node_path = self.node_path(bucket_id);
            let mut block_ids = Vec::new();
            for block_index in 0..self.args.z {
                block_ids.push(*y.get(&block_index).unwrap())
            }
            self.write_empty_bucket(block_ids, node_path);
        }
        debug!("...done!");
    }

    /// Reads all the blocks from the bucket with ID `bucket_id`.
    fn read_bucket(&self, bucket_id: i64) -> Vec<Block> {
        let bucket_path = self.node_path(bucket_id);
        self.raw_read_bucket(bucket_path)
    }

    /// Write blocks to bucket with ID `bucket_id`
    #[allow(clippy::comparison_chain)]
    fn write_bucket(&mut self, bucket_id: i64, mut blocks: Vec<Block>) {
        let missing_blocks = self.args.z - blocks.len() as i64;
        if missing_blocks > 0 {
            let empty_block_contents = Bytes::from(vec![0u8; self.args.b as usize]);

            // pad blocks
            for _ in 0..missing_blocks {
                blocks.push(Block {
                    id: -1,
                    payload: empty_block_contents.clone(),
                });
            }
        } else if missing_blocks < 0 {
            panic!("Error: trying to write more blocks than the bucket can hold");
        } else {
            // do nothing
        }

        // write blocks to bucket
        let node_path = self.node_path(bucket_id);
        self.raw_write_bucket(node_path, blocks);
    }

    /// Write empty blocks with the specified IDs to the given bucket
    pub fn write_empty_bucket(&mut self, block_ids: Vec<i64>, node_path: String) {
        let empty_block_contents = Bytes::from(vec![0u8; self.args.b as usize]);
        let mut blocks = Vec::new();

        for block_id in block_ids {
            blocks.push(Block {
                id: block_id,
                payload: empty_block_contents.clone(),
            });
        }

        // write blocks to bucket
        self.raw_write_bucket(node_path, blocks);
    }

    /// Return the blocks in the bucket at given path.
    ///
    /// Note that if encryption is enabled (default),
    /// the bucket is decrypted after being read.
    fn raw_read_bucket(&self, path: String) -> Vec<Block> {
        let file_contents = self.io.read_file(path);

        let bucket: Bucket = match self.encryption_key.is_empty() {
            true => bincode::deserialize(file_contents.as_slice()).unwrap(),
            false => {
                let encrypted_bytes: EncryptedBytes =
                    bincode::deserialize(file_contents.as_slice()).unwrap();
                self.decrypt_bucket(encrypted_bytes)
            }
        };

        bucket.blocks
    }

    /// Write the given blocks to the bucket at given path.
    ///
    /// Note that if encryption is enabled (default),
    /// The bucket is encrypted before being written.
    fn raw_write_bucket(&mut self, path: String, blocks: Vec<Block>) {
        let bucket = Bucket {
            blocks,
            format: self.name(),
            version: String::from("1.0"),
        };

        let bytes: Vec<u8> = match self.encryption_key.is_empty() {
            true => bincode::serialize(&bucket).unwrap(),
            false => {
                let encrypted_bytes = self.encrypt_bucket(bucket);
                bincode::serialize(&encrypted_bytes).unwrap()
            }
        };

        self.io.write_file(path, bytes.as_slice());
    }

    /// Encrypt a bucket and return the ciphertext and IV
    fn encrypt_bucket(&self, bucket: Bucket) -> EncryptedBytes {
        let mut data = bincode::serialize(&bucket).unwrap();
        let iv = self.encrypt(&mut data);

        let mut bm = BytesMut::new();
        bm.extend_from_slice(&data);

        EncryptedBytes {
            iv: Bytes::from(iv),
            ciphertext: bm,
        }
    }

    /// Decrypt a bucket, given the ciphertext and IV
    fn decrypt_bucket(&self, encrypted_bytes: EncryptedBytes) -> Bucket {
        let mut data = encrypted_bytes.ciphertext;
        let ciphertext = data.as_byte_slice_mut();

        self.decrypt(encrypted_bytes.iv.bytes(), ciphertext);

        let bucket: Bucket = bincode::deserialize(&ciphertext).unwrap();
        bucket
    }

    /// Encrypt the given data
    fn encrypt(&self, mut data: &mut [u8]) -> Vec<u8> {
        match &self.args.cipher[..] {
            "aes-ctr" => {
                let iv = thread_rng().gen::<[u8; 16]>(); // AES-CTR

                // AES-CTR
                let key = GenericArray::from_slice(&self.encryption_key);
                let nonce = GenericArray::from_slice(&iv);
                let mut cipher = Aes128Ctr::new(key, nonce);
                cipher.apply_keystream(&mut data);
                iv.to_vec()
            }
            _ => {
                let iv = thread_rng().gen::<[u8; 12]>(); // ChaCha

                // ChaCha
                let key = Key::from_slice(&self.encryption_key);
                let nonce = Nonce::from_slice(&iv);
                let mut cipher = ChaCha8::new(&key, &nonce);
                cipher.apply_keystream(&mut data);
                iv.to_vec()
            }
        }
    }

    /// Decrypt the given data
    fn decrypt(&self, iv: &[u8], mut data: &mut [u8]) {
        match &self.args.cipher[..] {
            "aes-ctr" => {
                // AES-CTR
                let key = GenericArray::from_slice(&self.encryption_key);
                let nonce = GenericArray::from_slice(&iv);
                let mut cipher = Aes128Ctr::new(key, nonce);
                cipher.apply_keystream(&mut data);
            }
            _ => {
                // ChaCha
                let key = Key::from_slice(self.encryption_key.as_slice());
                let nonce = Nonce::from_slice(iv);
                let mut cipher = ChaCha8::new(&key, &nonce);
                cipher.apply_keystream(&mut data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use crate::{ORAMConfig, PathORAM};
    use crate::io::MemoryIOService;

    fn cli_for_oram(disable_encryption: bool) -> ORAMConfig {
        let mut args = ORAMConfig {
            name: "".to_string(),
            private_directory: "private".to_string(),
            public_directory: "public".to_string(),
            mountpoint: "".to_string(),
            algorithm: "".to_string(),
            cipher: "".to_string(),
            client_data_dir: "".to_string(),
            encryption_key_file: "".to_string(),
            encryption_passphrase: "".to_string(),
            io: "".to_string(),
            n: 0,
            z: 0,
            b: 0,
            init: false,
            disable_encryption,
            manual: false,
            foreground: false,
            interactive: false,
        };
        args.algorithm = "pathoram".to_string();
        args.disable_encryption = disable_encryption;
        args.init = true;
        args.foreground = false;
        args.manual = true;
        args.io = "memory".to_string();
        args.n = 255;
        args.z = 4;
        args.b = 16384;
        args
    }

    #[test]
    fn test_access() {
        let disable_encryption = true;
        let args = cli_for_oram(disable_encryption);

        let io = Box::new(MemoryIOService::new());
        let mut pathoram = PathORAM::new(&args, io);
        pathoram.setup();

        assert_eq!(pathoram.verify_main_invariant(), true);

        let data = Bytes::from(vec![43; args.b as usize]);
        let _ = pathoram.access("write", 1, Some(data.clone()));

        let read_bytes = pathoram.access("read", 1, None).unwrap();

        println!("{:?}", data);
        println!("{:?}", read_bytes);

        assert_eq!(data, read_bytes);
    }

    #[test]
    fn test_encryption() {
        let disable_encryption = false;
        let mut args = cli_for_oram(disable_encryption);
        args.cipher = "chacha8".to_string();
        let io = Box::new(MemoryIOService::new());

        let mut pathoram = PathORAM::new(&args, io);
        pathoram
            .io
            .write_file(args.encryption_key_file.clone(), vec![66; 32].as_slice());
        pathoram.setup();

        assert_eq!(pathoram.verify_main_invariant(), true);

        let data = Bytes::from(vec![43; args.b as usize]);
        let _ = pathoram.access("write", 1, Some(data.clone()));

        let read_bytes = pathoram.access("read", 1, None).unwrap();

        println!("{:?}", data);
        println!("{:?}", read_bytes);

        assert_eq!(data, read_bytes);
    }
}
