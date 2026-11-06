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

//! Decoded image metadata retained for relocation and linking.

use alloc::vec::Vec;

use super::{relocate::RelocatedImage, LoadRequest};
use crate::{
    elf::{DynamicInfo, LoadSegmentInfo, RelocationRecord},
    error::LoadStage,
    memory::{ImageMapping, TargetAddress, TargetRange},
    relocation, LoadResult,
};

#[must_use = "retain the decoded image to keep its allocation alive"]
pub(crate) struct DecodedImage<A: ImageMapping> {
    pub(super) allocation: A,
    pub(super) request: LoadRequest,
    pub(super) segments: Vec<LoadSegmentInfo>,
    pub(super) relro: Option<TargetRange>,
    pub(super) image_range: TargetRange,
    pub(super) entry: Option<TargetAddress>,
    pub(super) dynamic: Option<DynamicInfo>,
    pub(super) relocations: Vec<RelocationRecord>,
}

impl<A: ImageMapping> DecodedImage<A> {
    pub(crate) fn relocate(self) -> LoadResult<RelocatedImage<A>> {
        self.relocate_inner()
            .map_err(|error| error.at_stage(LoadStage::Relocate))
    }

    fn relocate_inner(mut self) -> LoadResult<RelocatedImage<A>> {
        relocation::apply(
            &mut self.allocation,
            self.request.profile(),
            &self.segments,
            self.image_range,
            &self.relocations,
        )?;
        Ok(RelocatedImage {
            allocation: self.allocation,
            request: self.request,
            segments: self.segments,
            relro: self.relro,
            image_range: self.image_range,
            entry: self.entry,
            dynamic: self.dynamic,
            relocations: self.relocations,
        })
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
    pub(crate) fn relocations(&self) -> &[RelocationRecord] {
        &self.relocations
    }
}
