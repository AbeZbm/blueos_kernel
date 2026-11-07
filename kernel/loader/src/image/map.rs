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

//! Initialized, segment-protected images and runtime metadata decoding.
//! Relocation, cache synchronization and RELRO protection follow later.

use super::decode::DecodedImage;
use crate::{
    elf::{DynamicInfo, ElfHeaderInfo, LoadSegmentInfo, RelocationRecord},
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    memory::{AllocationOffset, ImageMapping, TargetAddress, TargetRange},
    LoadError, LoadRequest, LoadResult,
};
use alloc::vec::Vec;

#[must_use = "keep the mapped image alive to retain its backing"]
pub(crate) struct MappedImage<A: ImageMapping> {
    pub(super) allocation: A,
    pub(super) request: LoadRequest,
    pub(super) header: ElfHeaderInfo,
    pub(super) segments: Vec<LoadSegmentInfo>,
    pub(super) dynamic: Option<DynamicInfo>,
    /// Original ELF virtual range, retained for protection after relocation.
    pub(super) relro: Option<TargetRange>,
    pub(super) image_range: TargetRange,
    pub(super) entry: Option<TargetAddress>,
}

impl<A: ImageMapping> MappedImage<A> {
    pub(crate) const fn allocation(&self) -> &A {
        &self.allocation
    }

    pub(crate) const fn entry(&self) -> Option<TargetAddress> {
        self.entry
    }

    /// Signed displacement, including allocations below the ELF's link address.
    pub(crate) fn load_bias(&self) -> i128 {
        i128::from(self.allocation.base().get()) - i128::from(self.image_range.start().get())
    }

    pub(crate) fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        self.allocation.read(offset, dst)
    }

    pub(crate) fn decode(self) -> LoadResult<DecodedImage<A>> {
        self.decode_inner()
            .map_err(|error| error.at_stage(LoadStage::Decode))
    }

    fn decode_inner(self) -> LoadResult<DecodedImage<A>> {
        let mut relocations = Vec::new();
        if let Some(dynamic) = &self.dynamic {
            let class = self.header.class();
            let mut total = 0u64;
            for table in dynamic.relocation_tables() {
                total = total
                    .checked_add(table.range.len() / table.format.entry_size(class))
                    .ok_or_else(|| {
                        LoadError::new(LoadErrorKind::IntegerOverflow, ErrorContext::None)
                    })?;
            }
            let capacity = usize::try_from(total).map_err(|_| {
                LoadError::new(
                    LoadErrorKind::ResourceLimit,
                    ErrorContext::Limit {
                        resource: LimitKind::RelocationCount,
                        actual: total,
                        maximum: usize::MAX as u64,
                    },
                )
            })?;
            relocations
                .try_reserve_exact(capacity)
                .map_err(|_| LoadError::new(LoadErrorKind::OutOfMemory, ErrorContext::None))?;
            let mut raw = [0; 24];
            for table in dynamic.relocation_tables() {
                if table.range.is_empty() {
                    continue;
                }
                let size = table.format.entry_size(class);
                let offset = AllocationOffset::new(
                    table.range.start().checked_sub(self.image_range.start())?,
                );
                for index in 0..table.range.len() / size {
                    self.allocation
                        .read(offset.checked_add(index * size)?, &mut raw[..size as usize])?;
                    relocations.push(RelocationRecord::decode(
                        &raw[..size as usize],
                        class,
                        self.header.endian(),
                        table.format,
                    )?);
                }
            }
        }
        Ok(DecodedImage {
            allocation: self.allocation,
            request: self.request,
            segments: self.segments,
            relro: self.relro,
            image_range: self.image_range,
            entry: self.entry,
            dynamic: self.dynamic,
            relocations,
        })
    }
}
