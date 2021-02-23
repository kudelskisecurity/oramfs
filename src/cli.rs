use structopt::StructOpt;

#[derive(Debug, StructOpt, Clone)]
#[structopt(name = "oramfs", about = "ORAM filesystem written in Rust")]
pub struct CLIArgs {
    #[structopt(subcommand)]
    pub cmd: CLISubCommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt, Debug, Clone)]
pub enum CLISubCommand {
    #[structopt(about = "List existing ORAMs", name = "ls")]
    List {
        #[structopt(long = "oneline", help = "Output only one line per ORAM configuration")]
        oneline: bool,
    },
    #[structopt(about = "Add an ORAM")]
    Add {
        #[structopt(name = "oram_name", help = "Name of the ORAM to add")]
        oram_name: String,
        #[structopt(name = "public", help = "Path to public directory")]
        public: String,
        #[structopt(name = "private", help = "Path to private directory")]
        private: String,

        #[structopt(
        long = "disable-encryption",
        visible_aliases = &["noenc"],
        help = "Disable encryption",
        )]
        disable_encryption: bool,

        #[structopt(
            long = "encryption-key-file",
            default_value = "/etc/oramfs/pathoram/encryption_key",
            help = "Path to the file containing the encryption key bytes"
        )]
        encryption_key_file: String,

        #[structopt(
        long = "alg",
        default_value = "pathoram",
        help = "ORAM scheme to use.",
        possible_values = &["fakeoram", "pathoram"],
        )]
        algorithm: String,

        #[structopt(
        long = "io",
        default_value = "disk",
        help = "IO Service to use.",
        possible_values = &["disk", "memory"],
        )]
        io: String,

        #[structopt(
            long = "client-data-dir",
            default_value = "/etc/oramfs/pathoram",
            help = "Path to the directory containing the client data"
        )]
        client_data_dir: String,

        #[structopt(
        long = "cipher",
        default_value = "chacha8",
        help = "Cipher to use for encryption.",
        possible_values = &["chacha8", "aes-ctr"],
        )]
        cipher: String,

        #[structopt(
            long = "non-interactive",
            help = "Ask configuration options interactively"
        )]
        non_interactive: bool,

        #[structopt(
            short = "p",
            long = "passphrase",
            default_value = "",
            help = "Encryption passphrase"
        )]
        encryption_passphrase: String,

        #[structopt(
            short = "m",
            long = "mountpoint",
            default_value = "mnt",
            help = "Path to directory to mount the FUSE ORAM at. \
        The directory will be created if it does not exist yet."
        )]
        mountpoint: String,

        #[structopt(
        short,
        long = "bucket-count",
        visible_aliases = &["nodes-count"],
        default_value = "255",
        help = "Number of buckets",
        )]
        n: i64,

        #[structopt(
        short,
        long = "blocks-per-bucket",
        visible_aliases = &["blocks-per-node"],
        default_value = "4",
        help = "Number of blocks per bucket",
        )]
        z: i64,

        #[structopt(
        short,
        long = "block-size",
        visible_aliases = &["bs"],
        default_value = "16384",
        help = "Block size in bytes",
        )]
        b: i64,
    },
    #[structopt(about = "Remove an existing ORAM", name = "rm")]
    Remove {
        #[structopt(name = "oram_name", help = "Name of the ORAM to remove.")]
        oram_name: String,
    },
    #[structopt(about = "Mount an ORAM")]
    Mount {
        #[structopt(name = "oram_name", help = "Name of the ORAM to mount.")]
        oram_name: String,

        #[structopt(
        long = "foreground",
        visible_aliases = &["f"],
        help = "Run in foreground.",
        )]
        foreground: bool,

        #[structopt(
            long,
            help = "Initialize the ORAM. Warning: some ORAMs perform destructive operations \
        on initialization. Make sure to use this option only the first time you create \
        your ORAM."
        )]
        init: bool,

        #[structopt(
        long = "manual",
        visible_aliases = &["nomount"],
        help = "Use manual mode. Do not mount ORAMFS automatically.",
        )]
        manual: bool,
    },
    #[structopt(about = "Unmount an ORAM")]
    Umount {
        #[structopt(name = "oram_name", help = "Name of the ORAM to unmount.")]
        oram_name: String,
    },
    #[structopt(about = "Enlarge an ORAM. This effectively doubles its size. \
        Note that the ORAM must be unmounted first.")]
    Enlarge {
        #[structopt(name = "oram_name", help = "Name of the ORAM to enlarge.")]
        oram_name: String,
    },
}
