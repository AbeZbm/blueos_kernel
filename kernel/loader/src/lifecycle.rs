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

//! Shared lifecycle primitives for standalone loading and dynamic linking.
//!
//! Read relocated init/fini pointers, validate their target addresses and preserve
//! one image's callback order. Image stages use this during finalization; the
//! dynamic linker can combine these per-image plans in dependency order. Graph
//! traversal, execution state and actual callback invocation belong to callers.

use crate::{
    elf::{read_u32, read_u64, DynamicInfo, LoadSegmentInfo},
    error::{ErrorContext, LoadErrorKind},
    memory::{AllocationOffset, MemoryPermissions, TargetAddress, TargetRange},
    profile::{ElfClass, LoadProfile},
    ImageMapping, LoadError, LoadResult,
};
use alloc::vec::Vec;
use goblin::elf::dynamic::{DT_FINI, DT_FINI_ARRAY, DT_INIT, DT_INIT_ARRAY, DT_PREINIT_ARRAY};

/// Addresses are valid only while the owning image remains alive.
/// These are target addresses, not typed host function pointers. The host
/// runtime determines the compatible calling ABI, arguments and execution
/// context, and chooses when to run the callbacks.
#[derive(Debug, Default)]
pub struct LifecyclePlan {
    preinit: Vec<TargetAddress>,
    init: Vec<TargetAddress>,
    fini: Vec<TargetAddress>,
}

impl LifecyclePlan {
    pub(crate) fn build(
        allocation: &impl ImageMapping,
        profile: &LoadProfile,
        segments: &[LoadSegmentInfo],
        image_range: TargetRange,
        dynamic: Option<&DynamicInfo>,
    ) -> LoadResult<Self> {
        let mut plan = Self::default();
        let Some(dynamic) = dynamic else {
            return Ok(plan);
        };
        let reader = LifecycleReader {
            allocation,
            profile,
            segments,
            image_range,
        };
        reader.array(&mut plan.preinit, dynamic, DT_PREINIT_ARRAY, false)?;
        reader.direct(&mut plan.init, dynamic, DT_INIT)?;
        reader.array(&mut plan.init, dynamic, DT_INIT_ARRAY, false)?;
        reader.array(&mut plan.fini, dynamic, DT_FINI_ARRAY, true)?;
        reader.direct(&mut plan.fini, dynamic, DT_FINI)?;
        Ok(plan)
    }

    /// Executable-only callbacks, run before ordinary initialization.
    pub fn preinit(&self) -> &[TargetAddress] {
        &self.preinit
    }

    /// DT_INIT first, followed by DT_INIT_ARRAY in forward order.
    pub fn init(&self) -> &[TargetAddress] {
        &self.init
    }

    /// DT_FINI_ARRAY in reverse order, followed by DT_FINI.
    pub fn fini(&self) -> &[TargetAddress] {
        &self.fini
    }
}

struct LifecycleReader<'a, A> {
    allocation: &'a A,
    profile: &'a LoadProfile,
    segments: &'a [LoadSegmentInfo],
    image_range: TargetRange,
}

impl<A: ImageMapping> LifecycleReader<'_, A> {
    fn direct(
        &self,
        functions: &mut Vec<TargetAddress>,
        dynamic: &DynamicInfo,
        tag: u64,
    ) -> LoadResult<()> {
        let Some(value) = dynamic.value(tag).filter(|value| *value != 0) else {
            return Ok(());
        };
        // Dynamic tags hold ELF virtual addresses, unlike relocated array slots.
        let offset = value
            .checked_sub(self.image_range.start().get())
            .ok_or_else(|| lifecycle_error(LoadErrorKind::OutOfBounds, tag, value))?;
        let function = self.allocation.base().checked_add(offset)?;
        self.push(functions, tag, function)
    }

    fn array(
        &self,
        functions: &mut Vec<TargetAddress>,
        dynamic: &DynamicInfo,
        tag: u64,
        reverse: bool,
    ) -> LoadResult<()> {
        let Some((_, range)) = dynamic.lifecycle_arrays().find(|(kind, _)| *kind == tag) else {
            return Ok(());
        };
        if range.is_empty() {
            return Ok(());
        }
        let (word_size, sentinel) = match self.profile.class() {
            ElfClass::Elf32 => (4, u64::from(u32::MAX)),
            ElfClass::Elf64 => (8, u64::MAX),
        };
        let offset = range.start().checked_sub(self.image_range.start())?;
        let runtime = self.allocation.base().checked_add(offset)?;
        if !runtime.get().is_multiple_of(word_size) {
            return Err(lifecycle_error(
                LoadErrorKind::InvalidAlignment,
                tag,
                runtime.get(),
            ));
        }
        let count = range.len() / word_size;
        let mut raw = [0; 8];
        for position in 0..count {
            let index = if reverse {
                count - 1 - position
            } else {
                position
            };
            // Geometry and its traversal budget were checked before allocation.
            let slot = AllocationOffset::new(offset).checked_add(index * word_size)?;
            self.allocation
                .read(slot, &mut raw[..word_size as usize])
                .map_err(|error| {
                    error.with_context(ErrorContext::DynamicTag {
                        tag,
                        value: range.start().get() + index * word_size,
                    })
                })?;
            let value = match self.profile.class() {
                ElfClass::Elf32 => u64::from(read_u32(&raw, 0, self.profile.endian())?),
                ElfClass::Elf64 => read_u64(&raw, 0, self.profile.endian())?,
            };
            // Preserve the existing loader convention for unused array slots.
            if value == 0 || value == sentinel {
                continue;
            }
            // Relocation already produced runtime pointers; do not bias them twice.
            self.push(functions, tag, TargetAddress::new(value))?;
        }
        Ok(())
    }

    fn push(
        &self,
        functions: &mut Vec<TargetAddress>,
        tag: u64,
        function: TargetAddress,
    ) -> LoadResult<()> {
        let mode = self.profile.entry_mode();
        let alignment = u64::from(mode.instruction_alignment());
        if function.get().checked_rem(alignment) != Some(0) {
            return Err(lifecycle_error(
                LoadErrorKind::InvalidAlignment,
                tag,
                function.get(),
            ));
        }
        let size = u64::from(mode.minimum_instruction_size());
        let vaddr = function
            .get()
            .checked_sub(self.allocation.base().get())
            .and_then(|offset| self.image_range.start().get().checked_add(offset));
        if !self.segments.iter().any(|segment| {
            segment.permissions().contains(MemoryPermissions::EXECUTE)
                && vaddr.is_some_and(|vaddr| {
                    TargetRange::new(segment.vaddr(), segment.memory_size())
                        .contains_span(TargetAddress::new(vaddr), size)
                })
        }) {
            return Err(lifecycle_error(
                LoadErrorKind::OutOfBounds,
                tag,
                function.get(),
            ));
        }
        functions
            .try_reserve(1)
            .map_err(|_| lifecycle_error(LoadErrorKind::OutOfMemory, tag, function.get()))?;
        functions.push(function);
        Ok(())
    }
}

fn lifecycle_error(kind: LoadErrorKind, tag: u64, value: u64) -> LoadError {
    LoadError::new(kind, ErrorContext::DynamicTag { tag, value })
}
