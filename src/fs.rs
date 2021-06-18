use std::ffi::OsStr;

use fuse::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyWrite, ReplyXattr, Request,
};
use libc::{c_int, ENOENT};
use log::info;
use time::Timespec;

use crate::Oramfs;

const TTL: Timespec = Timespec { sec: 1, nsec: 0 };
const UNIX_EPOCH: Timespec = Timespec { sec: 0, nsec: 0 };
pub const BIG_FILE_NAME: &str = "oram";
const MOUNTPOINT_INO: u64 = 1;
const BIG_FILE_INO: u64 = 2;

/// Attributes of the private directory
const PRIVATE_DIR_ATTR: FileAttr = FileAttr {
    ino: MOUNTPOINT_INO,
    size: 4096,
    blocks: 8,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
};

/// Attributes of the "oram" file within the private directory
const BIG_FILE_ATTR: FileAttr = FileAttr {
    ino: BIG_FILE_INO,
    size: 10_000_000,
    blocks: 1,
    atime: UNIX_EPOCH,
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::RegularFile,
    perm: 0o644,
    nlink: 1,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
};

/// Implement the FUSE operations necessary to get the ORAMFS working
impl Filesystem for Oramfs<'_> {
    fn init(&mut self, _req: &Request) -> Result<(), c_int> {
        Ok(())
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == MOUNTPOINT_INO && name.to_str() == Some(BIG_FILE_NAME) {
            let mut attr = BIG_FILE_ATTR;
            attr.size = self.oram_size;
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            MOUNTPOINT_INO => reply.attr(&TTL, &PRIVATE_DIR_ATTR),
            BIG_FILE_INO => {
                let mut attr = BIG_FILE_ATTR;
                attr.size = self.oram_size;
                reply.attr(&TTL, &attr)
            }
            _ => reply.error(ENOENT),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<Timespec>,
        _mtime: Option<Timespec>,
        _fh: Option<u64>,
        _crtime: Option<Timespec>,
        _chgtime: Option<Timespec>,
        _bkuptime: Option<Timespec>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match ino {
            MOUNTPOINT_INO => reply.attr(&TTL, &PRIVATE_DIR_ATTR),
            BIG_FILE_INO => {
                let mut attr = BIG_FILE_ATTR;
                attr.size = self.oram_size;
                reply.attr(&TTL, &attr)
            }
            _ => reply.error(ENOENT),
        }
    }

    fn open(&mut self, _req: &Request, ino: u64, _flags: u32, reply: ReplyOpen) {
        match ino {
            BIG_FILE_INO => reply.opened(0, 0),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        match ino {
            BIG_FILE_INO => {
                let bytes_read = self.split_read(size, offset);
                self.oram.post_op();
                reply.data(bytes_read.as_slice());
            }
            _ => reply.error(ENOENT),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _flags: u32,
        reply: ReplyWrite,
    ) {
        match ino {
            BIG_FILE_INO => {
                let bytes_written = self.split_write(offset, data);
                self.oram.post_op();
                reply.written(bytes_written);
            }
            _ => reply.error(ENOENT),
        }
    }

    fn flush(&mut self, _req: &Request, _ino: u64, _fh: u64, _lock_owner: u64, reply: ReplyEmpty) {
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _flags: u32,
        _lock_owner: u64,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        info!("FS Cleanup...");
        self.cleanup();
        reply.ok();
    }

    fn fsync(&mut self, _req: &Request, _ino: u64, _fh: u64, _datasync: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        match ino {
            MOUNTPOINT_INO => {
                let entries = vec![
                    (MOUNTPOINT_INO, FileType::Directory, "."),
                    (MOUNTPOINT_INO, FileType::Directory, ".."),
                    (BIG_FILE_INO, FileType::RegularFile, BIG_FILE_NAME),
                ];

                for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    // i + 1 means the index of the next entry
                    reply.add(entry.0, (i + 1) as i64, entry.1, entry.2);
                }
                reply.ok();
            }
            _ => reply.error(ENOENT),
        }
    }

    fn getxattr(&mut self, _req: &Request, ino: u64, _name: &OsStr, _size: u32, reply: ReplyXattr) {
        match ino {
            BIG_FILE_INO => reply.error(ENOENT),
            _ => reply.error(ENOENT),
        };
    }

    fn access(&mut self, _req: &Request, _ino: u64, _mask: u32, reply: ReplyEmpty) {
        reply.ok();
    }
}
