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

//! A finalized image retaining its mapping, lifecycle plan and runtime metadata.

use crate::{
    elf::{DynamicInfo, LoadSegmentInfo},
    lifecycle::LifecyclePlan,
    memory::{ImageMapping, ProtectionLevel, TargetAddress, TargetRange},
    LoadRequest,
};
use alloc::vec::Vec;

/// Memory finalization does not execute initialization or start the application.
#[must_use = "retain the sealed image to keep its allocation alive"]
pub(crate) struct SealedImage<A: ImageMapping> {
    pub(crate) allocation: A,
    pub(super) request: LoadRequest,
    pub(super) segments: Vec<LoadSegmentInfo>,
    pub(super) image_range: TargetRange,
    pub(crate) entry: Option<TargetAddress>,
    pub(super) dynamic: Option<DynamicInfo>,
    pub(super) relro: Option<TargetRange>,
    pub(super) protection_level: ProtectionLevel,
    pub(crate) lifecycle: LifecyclePlan,
}

impl<A: ImageMapping> SealedImage<A> {
    pub(crate) const fn lifecycle(&self) -> &LifecyclePlan {
        &self.lifecycle
    }

    pub(crate) const fn allocation(&self) -> &A {
        &self.allocation
    }

    pub(crate) const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    pub(crate) fn dynamic(&self) -> Option<&DynamicInfo> {
        self.dynamic.as_ref()
    }

    pub(crate) const fn relro(&self) -> Option<TargetRange> {
        self.relro
    }

    pub(crate) const fn protection_level(&self) -> ProtectionLevel {
        self.protection_level
    }
}
