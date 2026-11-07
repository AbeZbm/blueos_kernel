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

//! Complete standalone loading and ownership of its finalized result.
//! Internal image stages remain reusable by the later dynamic linker.

mod loaded;
pub use loaded::LoadedImage;

use crate::{
    error::LoadStage,
    image::ImageLoader,
    profile::{LoadLimits, LoadProfile, LoadPurpose},
    CodeCache, ElfReader, ImageAllocator, LoadResult,
};

/// Parameters for one single-image loading attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadRequest {
    profile: LoadProfile,
    limits: LoadLimits,
    purpose: LoadPurpose,
}

impl LoadRequest {
    /// Require an application entry unless changed to `SharedObject`.
    pub const fn new(profile: LoadProfile, limits: LoadLimits) -> Self {
        Self {
            profile,
            limits,
            purpose: LoadPurpose::Executable,
        }
    }

    pub const fn with_purpose(mut self, purpose: LoadPurpose) -> Self {
        self.purpose = purpose;
        self
    }

    pub const fn purpose(&self) -> LoadPurpose {
        self.purpose
    }

    pub const fn profile(&self) -> &LoadProfile {
        &self.profile
    }

    pub const fn limits(&self) -> &LoadLimits {
        &self.limits
    }
}

/// Load and finalize one self-contained ELF without executing its code.
///
/// Accepts fixed-address ET_EXEC and relocatable ET_DYN images admitted by
/// `request.profile()`. DT_NEEDED dependencies are rejected before allocation;
/// relocations must be NONE or supported explicit-addend RELATIVE records.
/// `SharedObject` permits a self-contained library without an entry, but does
/// not enable dependency loading or symbol binding.
///
/// The reader is consumed and released once copying completes, or on failure.
/// The host supplies its concrete reader, which may also be borrowed. The mapping must
/// outlive every use of the returned entry and lifecycle addresses. Loading
/// failures and discarding the result release backing through the mapping's
/// Drop implementation; they do not execute finalizers or restore old bytes.
///
/// The host supplies initial read/write backing, permission changes and code
/// cache synchronization. Successful loading does not initialize the application
/// runtime or authorize calls from a context incompatible with that backend.
pub fn load_elf<R, M, C>(
    reader: R,
    request: LoadRequest,
    allocator: M,
    cache: &mut C,
) -> LoadResult<LoadedImage<M::Allocation>>
where
    R: ElfReader,
    M: ImageAllocator,
    C: CodeCache + ?Sized,
{
    let planned = ImageLoader::new(reader, request)
        .admit()?
        .inspect()?
        .plan()?;
    if let Some(dynamic) = planned.dynamic() {
        request
            .profile()
            .check_standalone_dynamic(dynamic)
            .map_err(|error| error.at_stage(LoadStage::Plan))?;
    }
    let sealed = planned
        .allocate(allocator)?
        .map()?
        .decode()?
        .relocate()?
        .seal(cache)?;
    Ok(LoadedImage::from_sealed(sealed))
}
