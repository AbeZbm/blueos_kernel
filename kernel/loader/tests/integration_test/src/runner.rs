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

use blueos_loader as loader;
use blueos_loader::{
    error::{ErrorContext, LoadErrorKind},
    memory::TargetRange,
    profile::{LoadLimits, LoadProfile},
    CodeCache, ElfReader, LoadError, LoadRequest, LoadResult,
};
#[path = "../../support/mod.rs"]
mod support;
use core::{cell::RefCell, ffi::CStr, marker::PhantomData};
use semihosting::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};
pub(super) use support::{FlatImageAllocation, MemoryMapper, MemoryRegion, SliceElfReader};

pub(super) fn request() -> LoadRequest {
    #[cfg(target_arch = "riscv32")]
    let profile = LoadProfile::riscv32();
    #[cfg(target_arch = "riscv64")]
    let profile = LoadProfile::riscv64();
    #[cfg(target_arch = "aarch64")]
    let profile = LoadProfile::aarch64();
    LoadRequest::new(profile, LoadLimits::DEFAULT)
}

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

    pub static TEST_REGIONS: [super::MemoryRegion; 1] = [unsafe {
        // SAFETY: the board reserves this mapped range for the fixture,
        // and tests access it only while their image owns the region claim.
        super::MemoryRegion::new(TEST_REGION_START, TEST_REGION_END, TEST_REGION_PERMISSIONS)
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
/// Disable timer preemption until their entry returns so local cache maintenance
/// covers the only CPU allowed to execute the loaded image, including SMP QEMU.
#[must_use = "retain the local execution context until the loaded fixture returns"]
pub(super) struct LocalCodeCache {
    _interrupts: blueos::support::DisableInterruptGuard,
    _local: PhantomData<*mut ()>,
}

impl LocalCodeCache {
    pub(super) fn new() -> Self {
        Self {
            _interrupts: blueos::support::DisableInterruptGuard::new(),
            _local: PhantomData,
        }
    }
}

impl CodeCache for LocalCodeCache {
    fn synchronize(&mut self, executable: TargetRange) -> LoadResult<()> {
        let end = executable.end()?;
        let context = || ErrorContext::TargetRange {
            start: executable.start(),
            len: executable.len(),
            align: 1,
        };
        let start = usize::try_from(executable.start().get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        let end = usize::try_from(end.get())
            .map_err(|_| LoadError::new(LoadErrorKind::IntegerOverflow, context()))?;
        if start == end {
            return Ok(());
        }
        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        // SAFETY: only this pinned test context executes the prepared code.
        unsafe {
            core::arch::asm!("fence.i", options(nostack, preserves_flags));
        }

        #[cfg(target_arch = "aarch64")]
        {
            let ctr: usize;
            // SAFETY: the integration runner executes in kernel context and the
            // flat backend retains a local mapping for the complete range.
            unsafe {
                core::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr,
                    options(nostack, preserves_flags));
                let data_line = 4usize << ((ctr >> 16) & 15);
                for address in (start & !(data_line - 1)..end).step_by(data_line) {
                    core::arch::asm!("dc cvau, {address}", address = in(reg) address,
                        options(nostack, preserves_flags));
                }
                core::arch::asm!("dsb ish", options(nostack, preserves_flags));
                let instruction_line = 4usize << (ctr & 15);
                for address in (start & !(instruction_line - 1)..end).step_by(instruction_line) {
                    core::arch::asm!("ic ivau, {address}", address = in(reg) address,
                        options(nostack, preserves_flags));
                }
                core::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
            }
        }
        Ok(())
    }
}
