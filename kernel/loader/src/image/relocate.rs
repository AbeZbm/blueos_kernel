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

//! A relocated image awaiting cache synchronization and final protection.

use super::seal::SealedImage;
use crate::{
    elf::{DynamicInfo, LoadSegmentInfo, RelocationRecord},
    error::{ErrorContext, LoadErrorKind, LoadStage},
    lifecycle::LifecyclePlan,
    memory::{AllocationOffset, ImageMapping, MemoryPermissions, TargetAddress, TargetRange},
    CodeCache, LoadError, LoadRequest, LoadResult,
};
use alloc::vec::Vec;

#[must_use = "retain the relocated image to keep its allocation alive"]
pub(crate) struct RelocatedImage<A: ImageMapping> {
    pub(super) allocation: A,
    pub(super) request: LoadRequest,
    pub(super) segments: Vec<LoadSegmentInfo>,
    pub(super) relro: Option<TargetRange>,
    pub(super) image_range: TargetRange,
    pub(super) entry: Option<TargetAddress>,
    pub(super) dynamic: Option<DynamicInfo>,
    pub(super) relocations: Vec<RelocationRecord>,
}

impl<A: ImageMapping> RelocatedImage<A> {
    pub(crate) fn seal<C: CodeCache + ?Sized>(self, cache: &mut C) -> LoadResult<SealedImage<A>> {
        self.seal_inner(cache)
            .map_err(|error| error.at_stage(LoadStage::Seal))
    }

    fn seal_inner<C: CodeCache + ?Sized>(mut self, cache: &mut C) -> LoadResult<SealedImage<A>> {
        let protection_level = self.allocation.protection_level();
        self.request
            .profile()
            .check_protection_level(protection_level)?;
        let base = self.allocation.base();
        base.checked_add(self.allocation.len())?;
        let lifecycle = LifecyclePlan::build(
            &self.allocation,
            self.request.profile(),
            &self.segments,
            self.image_range,
            self.dynamic.as_ref(),
        )?;
        // Ordinary segment permissions are already active. Publish completed
        // code writes before execution and before closing writable RELRO.
        for segment in &self.segments {
            if segment.permissions().contains(MemoryPermissions::EXECUTE) {
                let start =
                    base.checked_add(segment.vaddr().checked_sub(self.image_range.start())?)?;
                cache
                    .synchronize(TargetRange::new(start, segment.memory_size()))
                    .map_err(|error| {
                        error.with_context(ErrorContext::TargetRange {
                            start,
                            len: segment.memory_size(),
                            align: 1,
                        })
                    })?;
            }
        }
        if let Some(relro) = self.relro.filter(|range| !range.is_empty()) {
            let segment = self
                .segments
                .iter()
                .find(|segment| {
                    TargetRange::new(segment.vaddr(), segment.memory_size())
                        .contains_span(relro.start(), relro.len())
                })
                .ok_or_else(|| {
                    LoadError::new(
                        LoadErrorKind::BadElf,
                        ErrorContext::TargetRange {
                            start: relro.start(),
                            len: relro.len(),
                            align: 0,
                        },
                    )
                })?;
            let offset =
                AllocationOffset::new(relro.start().checked_sub(self.image_range.start())?);
            self.allocation
                .set_permissions(
                    offset,
                    relro.len(),
                    segment.permissions().without(MemoryPermissions::WRITE),
                )
                .map_err(|error| {
                    error.with_context(ErrorContext::MemoryAccess {
                        allocation_base: base,
                        allocation_len: self.allocation.len(),
                        allocation_align: self.allocation.align(),
                        offset: offset.value(),
                        len: relro.len(),
                    })
                })?;
        }
        Ok(SealedImage {
            allocation: self.allocation,
            request: self.request,
            segments: self.segments,
            image_range: self.image_range,
            entry: self.entry,
            dynamic: self.dynamic,
            relro: self.relro,
            protection_level,
            lifecycle,
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
