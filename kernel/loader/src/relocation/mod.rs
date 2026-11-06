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

//! Checked single-image RELATIVE writes through an owning memory mapping.
//! Profile admission and all record checks finish before the first write.

use crate::{
    elf::{ElfClass, ElfData, LoadSegmentInfo, RelocationRecord},
    error::{ErrorContext, LoadErrorKind},
    memory::{AllocationOffset, ImageMapping, MemoryPermissions, TargetRange},
    profile::LoadProfile,
    LoadError, LoadResult,
};
use alloc::vec::Vec;

struct PlannedWrite {
    offset: AllocationOffset,
    value: u64,
    record_index: usize,
}

pub(crate) fn apply(
    allocation: &mut impl ImageMapping,
    profile: &LoadProfile,
    segments: &[LoadSegmentInfo],
    image_range: TargetRange,
    records: &[RelocationRecord],
) -> LoadResult<()> {
    let width = match profile.class() {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    let base = allocation.base();
    let bias = i128::from(base.get()) - i128::from(image_range.start().get());
    let mut writes: Vec<PlannedWrite> = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let Some(addend) = profile.check_relative_relocation(record)? else {
            continue;
        };
        let fail = |kind| record_error(record, kind);
        if record.symbol_index != 0 {
            return Err(fail(LoadErrorKind::BadElf));
        }
        if !record.offset.get().is_multiple_of(width) {
            return Err(fail(LoadErrorKind::InvalidAlignment));
        }
        let segment = segments
            .iter()
            .find(|segment| {
                TargetRange::new(segment.vaddr(), segment.memory_size())
                    .contains_span(record.offset, width)
            })
            .ok_or_else(|| fail(LoadErrorKind::OutOfBounds))?;
        if !segment.permissions().contains(MemoryPermissions::WRITE) {
            return Err(fail(LoadErrorKind::PermissionConflict));
        }
        let offset = record
            .offset
            .checked_sub(image_range.start())
            .map_err(|_| fail(LoadErrorKind::OutOfBounds))?;
        if offset
            .checked_add(width)
            .is_none_or(|end| end > allocation.len())
        {
            return Err(fail(LoadErrorKind::OutOfBounds));
        }
        let runtime = base
            .checked_add(offset)
            .map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
        runtime
            .checked_add(width)
            .map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
        if !runtime.get().is_multiple_of(width) {
            return Err(fail(LoadErrorKind::InvalidAlignment));
        }
        let value = u64::try_from(bias + i128::from(addend))
            .map_err(|_| fail(LoadErrorKind::IntegerOverflow))?;
        if profile.class() == ElfClass::Elf32 && value > u64::from(u32::MAX) {
            return Err(fail(LoadErrorKind::IntegerOverflow));
        }
        writes
            .try_reserve(1)
            .map_err(|_| fail(LoadErrorKind::OutOfMemory))?;
        writes.push(PlannedWrite {
            offset: AllocationOffset::new(offset),
            value,
            record_index: index,
        });
    }
    writes.sort_unstable_by_key(|write| write.offset.value());
    for pair in writes.windows(2) {
        if pair[0].offset.value() + width > pair[1].offset.value() {
            return Err(record_error(
                &records[pair[1].record_index],
                LoadErrorKind::BadElf,
            ));
        }
    }
    for write in writes {
        let mut bytes = [0; 8];
        match (profile.class(), profile.endian()) {
            (ElfClass::Elf32, ElfData::Little) => {
                bytes[..4].copy_from_slice(&(write.value as u32).to_le_bytes())
            }
            (ElfClass::Elf32, ElfData::Big) => {
                bytes[..4].copy_from_slice(&(write.value as u32).to_be_bytes())
            }
            (ElfClass::Elf64, ElfData::Little) => bytes.copy_from_slice(&write.value.to_le_bytes()),
            (ElfClass::Elf64, ElfData::Big) => bytes.copy_from_slice(&write.value.to_be_bytes()),
        }
        let record = &records[write.record_index];
        allocation
            .write(write.offset, &bytes[..width as usize])
            .map_err(|error| {
                error.with_context(ErrorContext::Relocation {
                    target: record.offset,
                    raw_type: record.raw_type,
                    symbol_index: record.symbol_index,
                })
            })?;
    }
    Ok(())
}

fn record_error(record: &RelocationRecord, kind: LoadErrorKind) -> LoadError {
    LoadError::relocation(record.offset, record.raw_type, record.symbol_index, kind)
}
