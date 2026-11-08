// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Host-file reads and native code publication for synchronous integration fixtures.

use blueos::application::adapters::KernelCodeCache;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    ElfReader, LoadError, LoadResult,
};
use core::{cell::RefCell, ffi::CStr};
use semihosting::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

#[cfg(loader_test_exec)]
pub(super) mod fixed {
    use blueos_loader as loader;

    const fn parse_hex(value: &str) -> usize {
        let bytes = value.as_bytes();
        if bytes.len() <= 2 || bytes[0] != b'0' || (bytes[1] != b'x' && bytes[1] != b'X') {
            panic!("loader test relocation value must be hexadecimal");
        }

        let mut index = 2;
        let mut result = 0usize;
        while index < bytes.len() {
            let digit = match bytes[index] {
                b'0'..=b'9' => (bytes[index] - b'0') as usize,
                b'a'..=b'f' => (bytes[index] - b'a' + 10) as usize,
                b'A'..=b'F' => (bytes[index] - b'A' + 10) as usize,
                _ => panic!("invalid loader test relocation hex value"),
            };
            result = result * 16 + digit;
            index += 1;
        }
        result
    }

    const fn parse_permissions(value: &str) -> loader::MemoryPermissions {
        let bytes = value.as_bytes();
        let mut index = 0;
        let mut permissions = loader::MemoryPermissions::NONE;
        while index < bytes.len() {
            let permission = match bytes[index] {
                b'r' => loader::MemoryPermissions::READ,
                b'w' => loader::MemoryPermissions::WRITE,
                b'x' => loader::MemoryPermissions::EXECUTE,
                _ => panic!("invalid loader test relocation permission"),
            };
            permissions = permissions.bitor(permission);
            index += 1;
        }
        permissions
    }

    pub const TEST_REGION_START: usize = parse_hex(env!("LOADER_TEST_RELOCATION_ORIGIN"));
    pub const TEST_REGION_END: usize =
        TEST_REGION_START + parse_hex(env!("LOADER_TEST_RELOCATION_LENGTH"));
    pub const TEST_REGION_PERMISSIONS: loader::MemoryPermissions =
        parse_permissions(env!("LOADER_TEST_RELOCATION_PERMISSIONS"));

    pub static TEST_REGIONS: [blueos::application::adapters::MemoryRegion; 1] = [unsafe {
        // SAFETY: the board reserves this mapped range for the fixture,
        // and tests access it only while their image owns the region claim.
        blueos::application::adapters::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_END,
            TEST_REGION_PERMISSIONS,
        )
    }];
}

#[must_use = "retain the open ELF file until its positional reads finish"]
pub(super) struct FileReader {
    file: RefCell<File>,
    len: u64,
}

impl FileReader {
    pub(super) fn open(path: &CStr) -> semihosting::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file: RefCell::new(file),
            len,
        })
    }
}

impl ElfReader for FileReader {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.len)
    }

    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        let len = dst.len() as u64;
        let context = || ErrorContext::FileRange {
            offset,
            len,
            file_len: self.len,
        };
        let end = offset
            .checked_add(len)
            .ok_or_else(|| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        if end > self.len {
            return Err(LoadError::new(LoadErrorKind::OutOfBounds, context()));
        }
        if dst.is_empty() {
            return Ok(());
        }
        let mut file = self.file.borrow_mut();
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(dst))
            .map_err(|_| LoadError::new(LoadErrorKind::Io, context()))
    }
}

/// These fixtures return synchronously and do not block or create threads.
/// Keep the test on one CPU until its entry returns so the kernel's local
/// cache maintenance covers the only CPU allowed to execute the loaded image,
/// including SMP QEMU.
#[must_use = "retain the interrupt guard until the loaded fixture returns"]
pub(super) fn pinned_cache() -> (blueos::support::DisableInterruptGuard, KernelCodeCache) {
    (
        blueos::support::DisableInterruptGuard::new(),
        KernelCodeCache::new(),
    )
}
