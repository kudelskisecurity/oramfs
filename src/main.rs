use std::fs::File;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use daemonize::Daemonize;
use structopt::StructOpt;

use oramfs::ORAMConfig;
use oramfs::ORAMManager;
use oramfs::ORAMFS;
use oramfs::{start, CLISubCommand};
use oramfs::{CLIArgs, BIG_FILE_NAME};

/// Start the ORAM in daemon or foreground mode, depending on options passed
fn start_oram(args: &mut ORAMConfig) {
    let args_clone = args.clone();

    if args.disable_encryption {
        println!("*****************************************************************************");
        println!("[WARNING]: Encryption is disabled. This is not secure. You have been warned!");
        println!("*****************************************************************************");
    }

    println!("Starting ORAM...");
    let oramfs = ORAMFS::new(&args);

    if !args.foreground {
        let stdout_log_path = "/tmp/oramfs.out";
        let stderr_log_path = "/tmp/oramfs.err";
        let stdout = File::create(stdout_log_path)
            .unwrap_or_else(|_| panic!("Failed to create stdout log file: {}", stdout_log_path));
        let stderr = File::create(stderr_log_path)
            .unwrap_or_else(|_| panic!("Failed to create stderr log file: {}", stderr_log_path));
        let daemonize = Daemonize::new()
            .stdout(stdout)
            .stderr(stderr)
            .working_directory(".")
            .exit_action(move || automount(args_clone));

        println!("Running as a daemon...");
        match daemonize.start() {
            Ok(_) => {
                println!("Successfully started daemon...");
                start(args.clone(), oramfs);
            }
            Err(e) => eprintln!("Failed to start daemon: {}", e),
        }
    } else {
        println!("Running in foreground...");
        start(args.clone(), oramfs);
    }
}

/// Automatically mount filesystem on top of the ORAMFS if `--manual` was not set
pub fn automount(args: ORAMConfig) {
    if !args.manual {
        sleep(Duration::from_millis(500));
        println!("Mounting filesystem to private directory...");
        mount_filesystem(args);
    }
}

/// Create loop device, optionally format EXT4 filesystem, and finally mount it
pub fn mount_filesystem(args: ORAMConfig) {
    let oram_file_path = String::from(
        Path::new(&args.mountpoint)
            .join(BIG_FILE_NAME)
            .to_str()
            .unwrap(),
    );

    if args.init {
        println!("Formatting EXT4 filesystem...");
        if !Command::new("mkfs.ext4")
            .arg("-F")
            .arg(oram_file_path.clone())
            .status()
            .unwrap()
            .success()
        {
            cleanup(args);
            panic!("Failed to format filesystem");
        }
    }

    let private = args.private_directory.clone();
    std::fs::create_dir_all(Path::new(&private)).expect("Failed to create private directory");

    println!("Mounting directory...");
    if !Command::new("mount")
        .arg("-o")
        .arg("sync")
        .arg(oram_file_path)
        .arg(private.clone())
        .status()
        .unwrap()
        .success()
    {
        cleanup(args);
        panic!("Failed to mount directory");
    }

    println!(
        "Setup complete! ORAM filesystem mounted to private directory at: {}",
        private
    );
}

/// Cleanup the automatically mounted filesystem.
///
/// Unmounts the mountpoint directory, detaches the loop devices and finally unmounts
/// the private directory.
pub fn cleanup(args: ORAMConfig) {
    println!("Unmounting private ORAM directory...");
    Command::new("umount")
        .arg(args.private_directory)
        .output()
        .expect("Failed to umount private ORAM directory");

    println!("Unmounting FUSE mountpoint...");
    Command::new("umount")
        .arg(args.mountpoint)
        .output()
        .expect("Failed to unmount FUSE mountpoint");

    println!("Cleanup complete!");
}

/// Mount the ORAM corresponding to the config with name `oram_name`
pub fn oram_mount(oram_name: String, cmd: CLISubCommand) {
    let mut config = ORAMManager::get_config();
    let mut found = false;
    for mut c in config.orams.iter_mut() {
        if c.name == oram_name {
            found = true;

            if let CLISubCommand::Mount {
                oram_name: _,
                foreground,
                init,
                manual,
            } = cmd
            {
                c.foreground = foreground;
                c.manual = manual;

                // autodetect whether init was performed
                if !c.init {
                    println!("It looks like this ORAM is mounting for the first time. Initializing it first...");
                    c.init = true;

                    // ask for passphrase first time
                    let passphrase = ORAMManager::get_passphrase_first_time();
                    c.encryption_passphrase = passphrase.clone();

                    // generate encryption key and save it encrypted to config file
                    c.encrypted_encryption_key = ORAMManager::generate_encryption_key(
                        c.name.clone(),
                        passphrase,
                        c.salt.clone(),
                        c.cipher.clone(),
                    );

                    // update init status in config file
                    ORAMManager::mark_init(c.name.clone());
                    c.init = true;
                } else {
                    c.init = init;

                    // ask for passphrase
                    let passphrase = ORAMManager::get_passphrase();
                    c.encryption_passphrase = passphrase.clone();

                    // check passphrase
                    let valid_passphrase = ORAMManager::is_passphrase_valid(
                        passphrase,
                        c.salt.clone(),
                        c.encrypted_encryption_key.clone(),
                    );
                    if !valid_passphrase {
                        eprintln!("[Error] Invalid passphrase. Aborting.");
                        return;
                    }
                }

                break;
            }
        }
    }

    if !found {
        eprintln!(
            "No such ORAM: {}. \nDid you want to add an ORAM first?",
            oram_name
        );
    } else {
        for mut oram_config in config.orams {
            if oram_config.name == oram_name {
                start_oram(&mut oram_config);
            }
        }
    }
}

/// Unmount the ORAM corresponding to the config with name `oram_name`
fn oram_umount(oram_name: String) {
    let config = ORAMManager::get_config();
    let oram_config: ORAMConfig;
    for c in config.orams {
        if c.name == oram_name {
            oram_config = c;
            cleanup(oram_config);
            return;
        }
    }

    eprintln!(
        "No such ORAM: {}. \nDid you want to add an ORAM first?",
        oram_name
    );
}

/// Main entry point
pub fn main() {
    env_logger::init();
    let args = CLIArgs::from_args();

    match args.cmd.clone() {
        CLISubCommand::List { oneline } => ORAMManager::list_orams(oneline),
        CLISubCommand::Add { oram_name, .. } => ORAMManager::add_oram(oram_name, args.cmd),
        CLISubCommand::Remove { oram_name } => ORAMManager::remove_oram(oram_name),
        CLISubCommand::Mount { oram_name, .. } => oram_mount(oram_name, args.cmd),
        CLISubCommand::Umount { oram_name } => oram_umount(oram_name),
        CLISubCommand::Enlarge { oram_name: _, .. } => ORAMManager::double(args.cmd),
    }
}
