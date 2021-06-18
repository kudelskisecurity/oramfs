use oramfs::ORAMConfig;

pub fn cli_for_oram(oram: String, disable_encryption: bool) -> ORAMConfig {
    let mut args = ORAMConfig {
        name: "".to_string(),
        private_directory: "private".to_string(),
        public_directory: "public".to_string(),
        mountpoint: "".to_string(),
        algorithm: "".to_string(),
        cipher: "".to_string(),
        client_data_dir: "".to_string(),
        encrypted_encryption_key: "".to_string(),
        encryption_passphrase: "".to_string(),
        salt: "".to_string(),
        io: "".to_string(),
        n: 0,
        z: 0,
        b: 0,
        init: false,
        disable_encryption,
        manual: false,
        foreground: false,
        interactive: false,
        phc: "".to_string(),
    };
    args.algorithm = oram;
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
