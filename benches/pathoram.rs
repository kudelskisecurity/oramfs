use criterion::{Criterion, criterion_group, criterion_main};

use oramfs::{BaseORAM, get_io, ORAMConfig, ORAMFS, PathORAM};

pub fn cli_for_oram(oram: String, disable_encryption: bool) -> ORAMConfig {
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

/// Benchmark oram.read() and oram.write() performance
fn bench_throughput(c: &mut Criterion) {
    let disable_encryption = true;
    let mut args = cli_for_oram("pathoram".to_string(), disable_encryption);
    args.init = true;

    let mut io = get_io(&args);
    let encryption_key = vec![33; 32];
    io.write_file(args.encryption_key_file.clone(), &encryption_key);
    let mut oram = PathORAM::new(&args, io);
    if args.init {
        oram.init();
    }
    let oram_size = oram.size() as u64;
    let mut oramfs = ORAMFS {
        oram: Box::new(oram),
        oram_size,
        args: &args,
    };

    // generate file in memory
    let file_length = 1_000_000;

    println!("ORAM size: {}", oramfs.oram_size);
    println!("File length: {}", file_length);

    let offset = 0;
    let file_bytes = vec![42; file_length as usize];

    // main invariant before write
    assert_eq!(oramfs.oram.test_state(), true);

    c.bench_function("read_write_throughput", |b| {
        b.iter(|| {
            // copy file
            let _ = oramfs.split_write(offset, &file_bytes);

            // compare written file to the original one
            let _ = oramfs.split_read(file_length as u32, offset);
        })
    });
}

/// Benchmark oram.init() performance
fn bench_init(c: &mut Criterion) {
    let disable_encryption = true;
    let mut args = cli_for_oram("pathoram".to_string(), disable_encryption);
    args.init = true;
    args.n = 4095;

    let io = get_io(&args);
    let mut oram = PathORAM::new(&args, io);

    c.bench_function("pathoram_init", |b| b.iter(|| oram.init()));

    assert_eq!(oram.verify_main_invariant(), true);
}

criterion_group!(benches, bench_throughput, bench_init);
criterion_main!(benches);
