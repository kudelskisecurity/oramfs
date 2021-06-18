use oramfs::Oramfs;

mod oram;

#[test]
fn test_copy_file_and_check() {
    let disable_encryption = true;
    let mut args = oram::cli_for_oram("fakeoram".to_string(), disable_encryption);
    args.init = false;

    let mut oramfs = Oramfs::new(&args);
    oramfs.oram.init(); // call it manually because init is false

    // generate file in memory
    let file_length = 1_000_000;
    let offset = 0;
    let file_bytes = vec![42; file_length];

    // copy file
    let _ = oramfs.split_write(offset, &file_bytes);

    // compare written file to the original one
    let bytes_read = oramfs.split_read(file_length as u32, offset);

    let mut same_bytes = 0;
    for i in 0..file_length as usize {
        let original_byte = file_bytes.get(i).unwrap();
        let byte_read = bytes_read.get(i).unwrap();

        if original_byte == byte_read {
            same_bytes += 1;
        }
    }

    assert_eq!(same_bytes, file_length);
}
