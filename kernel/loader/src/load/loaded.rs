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

//! The public owner of a fully finalized standalone image.

use crate::{
    image::SealedImage,
    memory::{ProtectionLevel, TargetAddress},
    ImageMapping, LifecyclePlan,
};

/// Retains image backing and its validated runtime addresses.
///
/// Move this owner into the application or runtime that retains the image.
/// Before dropping it, the host must finish execution, any desired finalization
/// and all other uses of its code or data. Drop only releases the mapping;
/// it does not run lifecycle callbacks or stop executing threads.
#[must_use = "retain the loaded image for as long as its code or data is in use"]
pub struct LoadedImage<A: ImageMapping> {
    allocation: A,
    entry: Option<TargetAddress>,
    lifecycle: LifecyclePlan,
}

impl<A: ImageMapping> LoadedImage<A> {
    pub(crate) fn from_sealed(image: SealedImage<A>) -> Self {
        Self {
            allocation: image.allocation,
            entry: image.entry,
            lifecycle: image.lifecycle,
        }
    }

    /// Backend-owned mapping, retained until this image is dropped.
    pub const fn allocation(&self) -> &A {
        &self.allocation
    }

    /// Runtime entry address. Executable requests always return Some, even
    /// when the runtime address is zero; a shared object may have no entry.
    pub const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    /// Ordered runtime callback addresses, not yet executed by the loader.
    pub const fn lifecycle(&self) -> &LifecyclePlan {
        &self.lifecycle
    }

    /// Protection actually provided by the backend for this mapping.
    pub fn protection_level(&self) -> ProtectionLevel {
        self.allocation.protection_level()
    }
}
