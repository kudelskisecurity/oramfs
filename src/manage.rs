use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use std::{fs, io};

use daemonize::Daemonize;
use serde::{Deserialize, Serialize};

use crate::{get_io, BaseORAM, CLISubCommand, PathORAM, BIG_FILE_NAME, ORAMFS};

const ORAMFS_CONFIG_FILE_PATH: &str = "~/.config/oramfs/oramfs.yml";

#[derive(Serialize, Deserialize, Clone)]
pub struct ORAMFSConfig {
    pub orams: Vec<ORAMConfig>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ORAMConfig {
    pub name: String,
    pub private_directory: String,
    pub public_directory: String,
    pub mountpoint: String,
    pub algorithm: String,
    pub cipher: String,
    pub client_data_dir: String,
    pub encryption_key_file: String,
    pub encryption_passphrase: String,
    pub io: String,
    pub n: i64,
    pub z: i64,
    pub b: i64,
    pub init: bool,
    pub disable_encryption: bool,
    pub manual: bool,
    pub foreground: bool,
    pub interactive: bool,
}

pub struct ORAMManager;

impl ORAMManager {
    pub fn config_path() -> String {
        String::from(&*shellexpand::tilde(ORAMFS_CONFIG_FILE_PATH))
    }

    pub fn list_orams(oneline: bool) {
        if let Ok(f) = std::fs::File::open(Self::config_path()) {
            let config: ORAMFSConfig = serde_yaml::from_reader(f).expect("Failed to load config");
            for oram in config.orams {
                if oneline {
                    println!("{}", oram.name);
                } else {
                    println!("* {}", oram.name);
                    println!("  ORAM scheme : {}", oram.algorithm);
                    println!("  Public dir  : {}", oram.public_directory);
                    println!("  Private dir : {}", oram.private_directory);
                    println!("  Mountpoint  : {}", oram.mountpoint);
                    println!("  Client data : {}", oram.client_data_dir);
                }
            }
        }
    }

    pub fn add_oram(oram_name: String, cmd: CLISubCommand) {
        let mut config = Self::get_config();

        // check that name is not already taken
        for c in config.orams.clone() {
            if c.name == oram_name {
                eprintln!("Error: an ORAM with this name already exists.");
                return;
            }
        }

        // all good, create new oram config
        if let CLISubCommand::Add {
            oram_name,
            public,
            private,
            disable_encryption,
            encryption_key_file,
            algorithm,
            io,
            client_data_dir,
            cipher,
            non_interactive,
            encryption_passphrase,
            mountpoint,
            n,
            z,
            b,
        } = cmd
        {
            // create directories if not exist
            std::fs::create_dir_all(private.clone()).unwrap_or_else(|_| {
                panic!("Failed to create private directory: {}", private.clone())
            });
            std::fs::create_dir_all(public.clone()).unwrap_or_else(|_| {
                panic!("Failed to create public directory: {}", public.clone())
            });

            let mut oram = ORAMConfig {
                name: oram_name.clone(),
                private_directory: String::from(
                    Path::new(&private)
                        .canonicalize()
                        .unwrap_or_else(|_| panic!("No such private directory: {}", private))
                        .to_str()
                        .unwrap(),
                ),
                public_directory: String::from(
                    Path::new(&public).canonicalize().unwrap().to_str().unwrap(),
                ),
                algorithm,
                cipher,
                b,
                z,
                n,
                io,
                disable_encryption,
                manual: false,
                client_data_dir,
                encryption_key_file,
                mountpoint: mountpoint.clone(),
                encryption_passphrase,
                interactive: false,
                init: false,
                foreground: false,
            };

            // ask for some params interactively
            if !non_interactive {
                Self::interactive_config(&mut oram);
            }

            // handle mountpoint directory
            std::fs::create_dir_all(oram.mountpoint.clone()).unwrap_or_else(|_| {
                panic!(
                    "Failed to create mountpoint directory: {}",
                    mountpoint.clone()
                )
            });

            oram.mountpoint = String::from(
                Path::new(&oram.mountpoint)
                    .canonicalize()
                    .unwrap()
                    .to_str()
                    .unwrap(),
            );

            config.orams.push(oram);

            Self::save_config(&config);
            println!("Successfully added ORAM {}.", oram_name);
        };
    }

    pub fn remove_oram(oram_name: String) {
        let mut config = Self::get_config();

        // check that name exists
        let mut found = false;
        for c in config.orams.clone() {
            if c.name == oram_name {
                found = true;
            }
        }

        if !found {
            eprintln!("No such ORAM: {}", oram_name);
            return;
        }

        config.orams.retain(|c| c.name != oram_name);
        Self::save_config(&config);
        println!("Successfully removed ORAM {}.", oram_name);
    }

    pub fn get_config() -> ORAMFSConfig {
        match std::fs::File::open(Self::config_path()) {
            Ok(f) => {
                let config: ORAMFSConfig =
                    serde_yaml::from_reader(f).expect("Failed to load config");
                config
            }
            Err(_) => {
                // create file if it doesn't exist
                match std::fs::create_dir_all(Path::new(&Self::config_path()).parent().unwrap()) {
                    Ok(_) => println!("Created config directory"),
                    Err(e) => panic!("Failed to create config directory: {}", e),
                }
                ORAMFSConfig { orams: vec![] }
            }
        }
    }

    pub fn get_oram_config(name: String) -> ORAMConfig {
        let config = Self::get_config();
        for oram_config in config.orams {
            if oram_config.name == name {
                return oram_config;
            }
        }
        panic!("No such config: {}", name);
    }

    pub fn save_config(config: &ORAMFSConfig) {
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(Self::config_path())
            .unwrap_or_else(|_| {
                panic!(
                    "Cannot open file in write mode: {}",
                    ORAMFS_CONFIG_FILE_PATH
                )
            });

        serde_yaml::to_writer(file, config).expect("Failed to write file");
    }

    /// Interactively ask ORAM parameters from the user
    pub fn interactive_config(args: &mut ORAMConfig) {
        Self::ask_oram_size(args);
        Self::ask_passphrase(args);
        Self::ask_client_data_dir(args);
        Self::ask_mountpoint(args);
    }

    /// Ask the ORAM size from the user and set it on the ORAMConfig instance
    pub fn ask_oram_size(args: &mut ORAMConfig) {
        loop {
            let mut oram_size_input = String::new();
            println!("Please enter desired ORAM total size in bytes, \nor press enter to use default [default: 16000000 (16 MB)]: ");
            io::stdin()
                .read_line(&mut oram_size_input)
                .expect("Failed to read ORAM size");

            let mut trimmed = oram_size_input.trim();

            if trimmed.is_empty() {
                trimmed = "16000000";
            }

            match trimmed.parse::<i64>() {
                Ok(oram_size) => {
                    let (n, z, b) = ORAMFS::params_for_size(oram_size);
                    args.n = n;
                    args.z = z;
                    args.b = b;
                    println!(
                        "Adjusting ORAM size to closest valid value: {} bytes",
                        (n * z * b)
                    );
                    break;
                }
                Err(_e) => {
                    println!("Not a valid number. Please input a valid number for the ORAM size.")
                }
            };
        }
    }

    /// Ask the user to input their passphrase
    ///
    /// The passphrase is directly set on the ORAMConfig instance
    pub fn ask_passphrase(args: &mut ORAMConfig) {
        // get encryption passphrase
        if !args.disable_encryption {
            let passphrase =
                rpassword::prompt_password_stdout("Please enter encryption passphrase: ")
                    .expect("Failed to read passphrase");
            args.encryption_passphrase = String::from(passphrase.trim());
        }
    }

    pub fn ask_client_data_dir(args: &mut ORAMConfig) {
        let mut client_data_dir_input = String::new();
        let default_client_data_dir = format!("/etc/oramfs/{}", args.name);
        println!(
                "Please enter path to client data directory to use, or press enter to use default [default: {}]:",
                default_client_data_dir
            );
        io::stdin()
            .read_line(&mut client_data_dir_input)
            .expect("Failed to read client data dir");

        let trimmed = client_data_dir_input.trim();
        let mut client_data_dir = default_client_data_dir;
        if !trimmed.is_empty() {
            client_data_dir = trimmed.to_string();
        }

        args.client_data_dir = client_data_dir;
    }

    pub fn ask_mountpoint(args: &mut ORAMConfig) {
        let mut mountpoint_input = String::new();
        let default_mountpoint = get_default_mountpoint(args);
        println!(
            "Please enter path to mointpoint directory to use, or press enter to use default [default: {}]:",
            default_mountpoint
        );
        io::stdin()
            .read_line(&mut mountpoint_input)
            .expect("Failed to read mountpoint directory");

        let trimmed = mountpoint_input.trim();
        let mut mountpoint = default_mountpoint;
        if !trimmed.is_empty() {
            mountpoint = trimmed.to_string();
        }

        args.mountpoint = mountpoint;
    }

    pub fn tmp_filename(old: i64, i: i64) -> String {
        format!("node_{}_{}.oram", old, i)
    }

    pub fn unique_tmp_node_path(old: i64, i: i64, args: &ORAMConfig) -> String {
        let filename = Self::tmp_filename(old, i);
        let path = Path::new(&args.public_directory);
        let node_path = path.join(filename);
        String::from(node_path.to_str().unwrap())
    }

    /// Enlarges an existing oram by doubling its number of nodes.
    /// This should be called when the oram is unmounted.
    pub fn double(oram_name: String) {
        let mut config = Self::get_config();
        let mut args: ORAMConfig;
        let mut found = false;
        for mut o in config.orams.iter_mut() {
            if o.name == oram_name {
                args = o.clone();
                found = true;

                if args.algorithm != "pathoram" {
                    panic!("Unsupported ORAM scheme.");
                }

                Self::do_double(&mut o);
            }
        }

        if !found {
            panic!(
                "No such ORAM: {}. \nDid you want to add an ORAM first?",
                oram_name
            );
        }
    }

    pub fn do_double(args: &mut ORAMConfig) {
        let mut config = Self::get_config();

        // update ORAM.n
        let old_n = args.n;
        let new_n = (old_n + 1) * 2 - 1;
        args.n = new_n;

        // save config back to file

        for o in config.orams.iter_mut() {
            if o.name == args.name {
                o.n = new_n;
            }
        }

        Self::save_config(&config);

        // update position map
        let io = get_io(&args);
        let mut pathoram = PathORAM::new(&args, io);

        pathoram.load();

        // existing blocks: update leafid = leafid * 2
        for (_block_id, leaf_id) in pathoram.position_map.iter_mut() {
            *leaf_id *= 2;
        }

        // new blocks: distribute z blocks per leaf
        let bucket_ids: Vec<i64> = pathoram.tree.leaves();

        let mut leaf_id = 0;
        let mut rbmap: HashMap<i64, HashMap<i64, i64>> = HashMap::new(); // bucket_id -> block_index_within_bucket -> block_id
        let mut block_id = old_n * args.z;

        for bucket_id in bucket_ids {
            for block_index in 0..args.z {
                PathORAM::mapmap_insert(&mut rbmap, &bucket_id, block_index, &block_id);
                pathoram.position_map.insert(block_id, leaf_id);

                block_id += 1;

                if block_index == args.z - 1 {
                    leaf_id += 1;
                }
            }
        }

        // save position map back to disk
        pathoram.save();

        // update public storage

        // existing buckets: rename node files to match new tree numbering n'=(n*2)+1
        // note that we use an intermediate tmp file to avoid files overwriting each other
        // this requires renaming in two passes
        for bucket_id in 0..old_n {
            // rename files according to new numbering
            let current_path = pathoram.node_path(bucket_id);
            let tmp_path = Self::unique_tmp_node_path(bucket_id, bucket_id * 2 + 1, &args);
            std::fs::rename(current_path.clone(), tmp_path.clone()).unwrap_or_else(|_| {
                panic!(
                    "Failed to rename node file to tmp file: {}, {}",
                    current_path, tmp_path
                )
            });
        }
        for bucket_id in 0..old_n {
            // rename files according to new numbering
            let tmp_path = Self::unique_tmp_node_path(bucket_id, bucket_id * 2 + 1, &args);
            let destination_path = pathoram.node_path(bucket_id * 2 + 1);
            std::fs::rename(tmp_path.clone(), destination_path.clone()).unwrap_or_else(|_| {
                panic!(
                    "Failed to rename tmp file to dest file: {}, {}",
                    tmp_path, destination_path
                )
            });
        }

        // new buckets: write empty blocks
        pathoram.init_public_storage(rbmap);

        let oram_size = (args.n * args.z * args.b) as u64;
        let args_clone = args.clone();
        let args_clone2 = args.clone();
        let args_clone3 = args.clone();
        let daemonize = Daemonize::new()
            .working_directory(".")
            .exit_action(move || Self::resize2fs_enlarge(args_clone3));

        println!("Running as a deamon...");
        if daemonize.start().is_ok() {
            let oramfs = ORAMFS {
                args: &args_clone,
                oram_size,
                oram: Box::new(pathoram),
            };
            start(args_clone2, oramfs);
        };
    }

    pub fn resize2fs_enlarge(args: ORAMConfig) {
        sleep(Duration::from_millis(500));

        // use resize2fs to extend to use max size
        let oram_file_path = Path::new(&args.mountpoint).join(BIG_FILE_NAME);
        let output = Command::new("resize2fs")
            .arg("-f")
            .arg(&oram_file_path)
            .output()
            .expect("Failed to resize ext4 filesystem.");

        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();

        // unmount ORAM
        Command::new("umount")
            .arg(args.mountpoint)
            .output()
            .expect("Failed to unmount ORAM.");
    }
}

/// Get a directory in /tmp matching the oram name such as /tmp/oramfs_{oram_name}
fn get_default_mountpoint(args: &mut ORAMConfig) -> String {
    // let parent = Path::new(&args.private_directory)
    //     .parent()
    //     .expect("Cannot find parent directory");
    // parent.join(&args.name).to_str().unwrap().to_string()
    let tmp = Path::new("/tmp");
    let mountpoint = tmp.join(format!("oramfs_{}", args.name));
    mountpoint.to_str().unwrap().to_string()
}

/// Start the ORAMFS
pub fn start(args: ORAMConfig, oramfs: ORAMFS) {
    // create mountpoint directory if not exists
    std::fs::create_dir_all(args.mountpoint.clone())
        .unwrap_or_else(|_| panic!("Failed to create mountpoint directory: {}", args.mountpoint));

    let options = ["-o", "rw", "-o", "fsname=oramfs"]
        .iter()
        .map(|o| o.as_ref())
        .collect::<Vec<&OsStr>>();

    println!("Mounting FUSE filesystem...");
    fuse::mount(oramfs, &args.mountpoint, &options).unwrap();
    println!("Goodbye.");
}

#[cfg(test)]
mod tests {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    use crate::TreeNode;

    #[test]
    fn test_tree_index_enlarge() {
        let old_n = 3;
        let new_n = (old_n + 1) * 2 - 1;
        let mut tree2 = TreeNode::create_tree(new_n);

        let leaves = tree2.leaves();
        assert_eq!(leaves.len(), old_n as usize + 1);

        let mut bucket_ids: Vec<i64> = tree2.leaves();
        bucket_ids.shuffle(&mut thread_rng());

        let z = 4;

        let mut new_block_ids = vec![];
        for bucket_id in bucket_ids {
            for _block_index in 0..z {
                new_block_ids.push(bucket_id);
            }
        }

        let old_block_ids: Vec<i64> = (0..(old_n)).map(|x| x * 2 + 1).collect();

        println!("{:?}", old_block_ids);
        println!("{:?}", new_block_ids);

        assert_eq!(old_block_ids.len(), old_n as usize);

        // verify that the 2 vectors are disjoint
        let mut disjoint = true;

        for blkid in &old_block_ids {
            if new_block_ids.contains(&blkid) {
                disjoint = false;
            }
        }
        for blkid in &new_block_ids {
            if old_block_ids.contains(&blkid) {
                disjoint = false;
            }
        }

        assert!(disjoint);
    }
}
