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

//! Loader entry points backed by the kernel's flat execution domain.

use super::adapters::{
    FlatImageAllocation, KernelCodeCache, MemoryMapper, MemoryRegion, SliceElfReader,
};
use blueos_loader::{
    load_elf, profile::LoadLimits, ElfReader, LoadRequest, LoadResult, LoadedImage,
};

/// Native loader profile selected by the build target.
#[cfg(target_arch = "riscv32")]
pub fn board_load_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::riscv32()
}

#[cfg(target_arch = "riscv64")]
pub fn board_load_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::riscv64()
}

#[cfg(target_arch = "aarch64")]
pub fn board_load_profile() -> blueos_loader::profile::LoadProfile {
    blueos_loader::profile::LoadProfile::aarch64()
}

/// Default request for a standalone executable using the native profile.
pub fn load_request() -> LoadRequest {
    LoadRequest::new(board_load_profile(), LoadLimits::DEFAULT)
}

/// Load and finalize one standalone image through a host-provided reader.
///
/// `regions` authorizes fixed-address placements. Relocatable images may use
/// `None` and are backed by the kernel heap. The returned image retains its
/// mapping and validated entry/lifecycle addresses; it does not execute them.
///
/// Code publication is current-execution-context only. The caller must keep
/// the image's execution on this context until a host-wide rendezvous is used;
/// otherwise it must provide a different `CodeCache` backend.
pub fn load_image<R: ElfReader>(
    reader: R,
    regions: Option<&'static [MemoryRegion]>,
) -> LoadResult<LoadedImage<FlatImageAllocation>> {
    let mut allocator = MemoryMapper::new(regions);
    let mut cache = KernelCodeCache::new();
    load_elf(reader, load_request(), &mut allocator, &mut cache)
}

/// Load and finalize an image held in a stable in-memory byte slice.
pub fn load_from_memory(
    bytes: &[u8],
    regions: Option<&'static [MemoryRegion]>,
) -> LoadResult<LoadedImage<FlatImageAllocation>> {
    load_image(SliceElfReader::new(bytes), regions)
}
