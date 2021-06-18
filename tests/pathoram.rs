use oramfs::{get_io, Oramfs};
use oramfs::{BaseORAM, PathORAM};

mod oram;

#[test]
fn test_init() {
    let disable_encryption = true;
    let mut args = oram::cli_for_oram("pathoram".to_string(), disable_encryption);
    args.init = true;
    args.n = 2047;

    let mut io = get_io(&args);
    let encryption_key = vec![33; 32];
    io.write_file(args.encrypted_encryption_key.clone(), &encryption_key);
    let mut oram = PathORAM::new(&args, io);
    if args.init {
        oram.init();
    }
}

#[test]
fn test_copy_file_and_check() {
    for _ in 0..1 {
        copy_file_and_check()
    }
}

fn copy_file_and_check() {
    let disable_encryption = true;
    let mut args = oram::cli_for_oram("pathoram".to_string(), disable_encryption);
    args.init = true;

    let mut io = get_io(&args);
    let encryption_key = vec![33; 32];
    io.write_file(args.encrypted_encryption_key.clone(), &encryption_key);
    let mut oram = PathORAM::new(&args, io);
    if args.init {
        oram.init();
    }
    let oram_size = oram.size() as u64;
    let mut oramfs = Oramfs {
        oram: Box::new(oram),
        oram_size,
        args: &args,
    };

    // generate file in memory
    let file_length = 10_000_000;

    println!("ORAM size: {}", oramfs.oram_size);
    println!("File length: {}", file_length);

    let offset = 0;
    let file_bytes = vec![42; file_length as usize];

    // copy file
    let _ = oramfs.split_write(offset, &file_bytes);

    // compare written file to the original one
    let bytes_read = oramfs.split_read(file_length as u32, offset);

    assert_eq!(bytes_read, file_bytes);
}

#[test]
fn test_main_invariant() {
    let disable_encryption = true;
    let mut args = oram::cli_for_oram("pathoram".to_string(), disable_encryption);
    args.init = true;

    let io = get_io(&args);
    let mut oram = PathORAM::new(&args, io);
    oram.init();

    assert_eq!(oram.verify_main_invariant(), true);
}
