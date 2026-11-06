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

//! Bounded PT_DYNAMIC parsing and validation of referenced ELF tables.
//! Addresses remain ELF virtual addresses; this module does not relocate memory.

use alloc::vec::Vec;
use goblin::elf::dynamic::{
    DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ,
    DT_FLAGS, DT_FLAGS_1, DT_GNU_HASH, DT_HASH, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_JMPREL,
    DT_NEEDED, DT_NULL, DT_PLTREL, DT_PLTRELSZ, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_REL,
    DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELSZ, DT_SONAME, DT_STRSZ, DT_STRTAB, DT_SYMENT,
    DT_SYMTAB,
};

use super::{
    read_u32, read_u64,
    relocation::{RelocationFormat, RelocationTable},
    ElfClass, FileRange, LoadSegmentInfo, ProgramHeaderInfo,
};
use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::{MemoryPermissions, TargetAddress, TargetRange},
    profile::{LoadLimits, LoadProfile},
    ElfReader, LoadError, LoadResult,
};

#[derive(Debug)]
struct DynamicEntry {
    tag: u64,
    value: u64,
}

const LIFECYCLE_ARRAYS: [(u64, u64); 3] = [
    (DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
    (DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
    (DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
];

/// Validated raw metadata; symbol and dependency decoding follow later.
/// Tag addresses remain in the ELF virtual address space, not runtime addresses.
#[derive(Debug)]
pub(crate) struct DynamicInfo {
    entries: Vec<DynamicEntry>,
    tables: [Option<RelocationTable>; 3],
}

impl DynamicInfo {
    pub(crate) fn value(&self, tag: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.value)
    }

    /// Preserve DT_NEEDED encounter order; values are dynstr offsets, not names.
    pub(crate) fn needed(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .filter(|entry| entry.tag == DT_NEEDED)
            .map(|entry| entry.value)
    }

    pub(crate) fn is_pie(&self) -> bool {
        self.value(DT_FLAGS_1).unwrap_or(0) & DF_1_PIE != 0
    }

    /// Whether any dynamic entry explicitly requests immediate binding.
    pub(crate) fn bind_now(&self) -> bool {
        self.value(DT_BIND_NOW).is_some()
            || self.value(DT_FLAGS).unwrap_or(0) & DF_BIND_NOW != 0
            || self.value(DT_FLAGS_1).unwrap_or(0) & DF_1_NOW != 0
    }

    pub(crate) fn relocation_tables(&self) -> impl Iterator<Item = &RelocationTable> {
        self.tables.iter().flatten()
    }

    /// Array geometry is validated before allocation; pointers are read after relocation.
    pub(crate) fn lifecycle_arrays(&self) -> impl Iterator<Item = (u64, TargetRange)> + '_ {
        LIFECYCLE_ARRAYS.into_iter().filter_map(|(tag, size_tag)| {
            Some((
                tag,
                TargetRange::new(TargetAddress::new(self.value(tag)?), self.value(size_tag)?),
            ))
        })
    }
}

pub(crate) fn read_dynamic(
    reader: &impl ElfReader,
    header: &ProgramHeaderInfo,
    segments: &[LoadSegmentInfo],
    profile: &LoadProfile,
    limits: &LoadLimits,
) -> LoadResult<DynamicInfo> {
    let class = profile.class();
    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    let bytes = header.file_size();
    if bytes == 0 || !bytes.is_multiple_of(entry_size) || bytes > header.memory_size() {
        return Err(dynamic_range_error(header.vaddr(), bytes));
    }
    // A dynamic table must describe the same file bytes as its load segment,
    // rather than pointing to BSS or an unrelated file-to-VA mapping.
    let file = vaddr_to_file_range(segments, header.vaddr(), bytes)?;
    if file.offset() != header.file_offset()
        || !segments.iter().any(|segment| {
            TargetRange::new(segment.vaddr(), segment.memory_size())
                .contains_span(header.vaddr(), header.memory_size())
        })
    {
        return Err(dynamic_range_error(header.vaddr(), bytes));
    }
    let mut info = DynamicInfo {
        entries: Vec::new(),
        tables: [None; 3],
    };
    let mut seen = 0u64;
    let mut raw = [0; 16];
    let mut terminated = false;
    for index in 0..bytes / entry_size {
        // Check before reading or reserving: padding must not drive allocation.
        limits.check_dynamic_entry_count(index + 1)?;
        let offset = index
            .checked_mul(entry_size)
            .and_then(|n| file.offset().checked_add(n))
            .ok_or_else(|| dynamic_range_error(header.vaddr(), bytes))?;
        reader.read_exact_at(offset, &mut raw[..entry_size as usize])?;
        let (tag, value) = match class {
            ElfClass::Elf32 => (
                u64::from(read_u32(&raw, 0, profile.endian())?),
                u64::from(read_u32(&raw, 4, profile.endian())?),
            ),
            ElfClass::Elf64 => (
                read_u64(&raw, 0, profile.endian())?,
                read_u64(&raw, 8, profile.endian())?,
            ),
        };
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        let bit = profile.check_dynamic_tag(tag, value)?;
        if tag != DT_NEEDED && seen & bit != 0 {
            return Err(dynamic_error(tag, value));
        }
        seen |= bit;
        info.entries.try_reserve(1).map_err(|_| {
            LoadError::new(
                LoadErrorKind::OutOfMemory,
                ErrorContext::DynamicTag { tag, value },
            )
        })?;
        info.entries.push(DynamicEntry { tag, value });
    }
    if !terminated {
        return Err(dynamic_error(DT_NULL, bytes));
    }
    validate_metadata(&info, segments, class, limits)?;
    info.tables = relocation_tables(&info, segments, class)?;
    let mut total = 0u64;
    for table in info.relocation_tables() {
        let len = table.range.len();
        total = total
            .checked_add(len / table.format.entry_size(class))
            .ok_or_else(|| dynamic_range_error(table.range.start(), len))?;
        limits.check_relocation_count(total)?;
    }
    Ok(info)
}

fn validate_metadata(
    info: &DynamicInfo,
    segments: &[LoadSegmentInfo],
    class: ElfClass,
    limits: &LoadLimits,
) -> LoadResult<()> {
    let strtab = info.value(DT_STRTAB);
    let strsz = info.value(DT_STRSZ);
    match (strtab, strsz) {
        (None, None) => {}
        (Some(address), Some(len)) => {
            if len != 0 {
                vaddr_to_file_range(segments, TargetAddress::new(address), len)
                    .map_err(|_| dynamic_error(DT_STRTAB, address))?;
            }
        }
        _ => return Err(dynamic_error(DT_STRTAB, 0)),
    }
    for offset in info.needed().chain(info.value(DT_SONAME)) {
        if strtab.is_none() || offset >= strsz.unwrap_or(0) {
            return Err(dynamic_error(DT_STRTAB, offset));
        }
    }
    match (info.value(DT_SYMTAB), info.value(DT_SYMENT)) {
        (None, None) => {}
        (Some(address), Some(size)) => {
            let expected = match class {
                ElfClass::Elf32 => 16,
                ElfClass::Elf64 => 24,
            };
            if size != expected {
                return Err(dynamic_error(DT_SYMENT, size));
            }
            vaddr_to_file_range(segments, TargetAddress::new(address), size)
                .map_err(|_| dynamic_error(DT_SYMTAB, address))?;
        }
        _ => return Err(dynamic_error(DT_SYMTAB, 0)),
    }
    for (tag, len) in [(DT_HASH, 8), (DT_GNU_HASH, 16)] {
        if let Some(address) = info.value(tag) {
            vaddr_to_file_range(segments, TargetAddress::new(address), len)
                .map_err(|_| dynamic_error(tag, address))?;
        }
    }
    let word_size = match class {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    };
    let mut total = [DT_INIT, DT_FINI]
        .into_iter()
        .filter(|tag| info.value(*tag).is_some_and(|value| value != 0))
        .count() as u64;
    for (tag, size_tag) in LIFECYCLE_ARRAYS {
        match (info.value(tag), info.value(size_tag)) {
            (None, None) => continue,
            (Some(address), Some(len)) => {
                if !len.is_multiple_of(word_size) {
                    return Err(dynamic_error(size_tag, len));
                }
                if len != 0 {
                    if !address.is_multiple_of(word_size) {
                        return Err(dynamic_error(tag, address));
                    }
                    // Zero-filled array slots in BSS are valid; file backing is
                    // unnecessary, but the complete array must remain readable.
                    if !segments.iter().any(|segment| {
                        segment.permissions().contains(MemoryPermissions::READ)
                            && TargetRange::new(segment.vaddr(), segment.memory_size())
                                .contains_span(TargetAddress::new(address), len)
                    }) {
                        return Err(dynamic_error(tag, address));
                    }
                }
                total = total
                    .checked_add(len / word_size)
                    .ok_or_else(|| dynamic_error(size_tag, len))?;
            }
            (Some(address), None) => return Err(dynamic_error(tag, address)),
            (None, Some(len)) => return Err(dynamic_error(size_tag, len)),
        }
    }
    limits.check_lifecycle_entry_count(total)?;
    Ok(())
}

fn table(
    segments: &[LoadSegmentInfo],
    address: Option<u64>,
    len: Option<u64>,
    entry_size: Option<u64>,
    format: RelocationFormat,
    class: ElfClass,
    tag: u64,
) -> LoadResult<Option<RelocationTable>> {
    match (address, len, entry_size) {
        (None, None, None) => Ok(None),
        (Some(address), Some(len), Some(size)) => {
            if size != format.entry_size(class) || !len.is_multiple_of(size) {
                return Err(dynamic_error(tag, size));
            }
            let range = TargetRange::new(TargetAddress::new(address), len);
            range.end()?;
            // Validate the original table before overlap normalization loses
            // its source tag and starting address.
            if len != 0 {
                vaddr_to_file_range(segments, range.start(), len)
                    .map_err(|_| dynamic_error(tag, address))?;
            }
            Ok(Some(RelocationTable { range, format }))
        }
        _ => Err(dynamic_error(tag, 0)),
    }
}

fn relocation_tables(
    info: &DynamicInfo,
    segments: &[LoadSegmentInfo],
    class: ElfClass,
) -> LoadResult<[Option<RelocationTable>; 3]> {
    let rel = table(
        segments,
        info.value(DT_REL),
        info.value(DT_RELSZ),
        info.value(DT_RELENT),
        RelocationFormat::Rel,
        class,
        DT_REL,
    )?;
    let rela = table(
        segments,
        info.value(DT_RELA),
        info.value(DT_RELASZ),
        info.value(DT_RELAENT),
        RelocationFormat::Rela,
        class,
        DT_RELA,
    )?;
    let plt = match (
        info.value(DT_JMPREL),
        info.value(DT_PLTRELSZ),
        info.value(DT_PLTREL),
    ) {
        (None, None, None) => None,
        (Some(address), Some(len), Some(format)) if format == DT_REL || format == DT_RELA => {
            let format = if format == DT_REL {
                RelocationFormat::Rel
            } else {
                RelocationFormat::Rela
            };
            table(
                segments,
                Some(address),
                Some(len),
                Some(format.entry_size(class)),
                format,
                class,
                DT_JMPREL,
            )?
        }
        _ => return Err(dynamic_error(DT_JMPREL, 0)),
    };
    let mut tables = [rel, rela, plt];
    // JMPREL may overlap the main table. Merge aligned, same-format ranges so
    // later eager relocation never applies the same table entry twice.
    for (i, tag) in [DT_REL, DT_RELA, DT_JMPREL].into_iter().enumerate() {
        let Some(current) = tables[i] else {
            continue;
        };
        let mut merged = false;
        for previous in tables[..i].iter_mut().flatten() {
            if !current.range.overlaps(previous.range) {
                continue;
            }
            let start = current.range.start().min(previous.range.start());
            let displacement = current
                .range
                .start()
                .get()
                .abs_diff(previous.range.start().get());
            if current.format != previous.format
                || !displacement.is_multiple_of(current.format.entry_size(class))
            {
                return Err(dynamic_error(tag, current.range.start().get()));
            }
            let end = current.range.end()?.max(previous.range.end()?);
            previous.range = TargetRange::new(start, end.checked_sub(start)?);
            merged = true;
            break;
        }
        if merged {
            tables[i] = None;
        }
    }
    Ok(tables)
}

/// Resolve an ELF virtual span to bytes contained in one file-backed load segment.
fn vaddr_to_file_range(
    segments: &[LoadSegmentInfo],
    address: TargetAddress,
    len: u64,
) -> LoadResult<FileRange> {
    for segment in segments {
        if TargetRange::new(segment.vaddr(), segment.file_range().len()).contains_span(address, len)
        {
            let displacement = address.checked_sub(segment.vaddr())?;
            let offset = segment
                .file_range()
                .offset()
                .checked_add(displacement)
                .ok_or_else(|| dynamic_range_error(address, len))?;
            return Ok(FileRange::new(offset, len));
        }
    }
    Err(dynamic_range_error(address, len))
}

fn dynamic_range_error(start: TargetAddress, len: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::TargetRange {
            start,
            len,
            align: 1,
        },
    )
}

fn dynamic_error(tag: u64, value: u64) -> LoadError {
    LoadError::new(
        LoadErrorKind::BadElf,
        ErrorContext::DynamicTag { tag, value },
    )
}
