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

//! ELF REL/RELA table descriptors and record decoding.
//! Architecture-specific relocation types remain raw; no memory is modified.

use super::{read_u32, read_u64, ElfClass, ElfData};
use crate::{
    memory::{TargetAddress, TargetRange},
    LoadResult,
};

/// On-disk record format, independent of the architecture's relocation types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelocationFormat {
    Rel,
    Rela,
}

impl RelocationFormat {
    pub(crate) const fn entry_size(self, class: ElfClass) -> u64 {
        match (class, self) {
            (ElfClass::Elf32, Self::Rel) => 8,
            (ElfClass::Elf32, Self::Rela) => 12,
            (ElfClass::Elf64, Self::Rel) => 16,
            (ElfClass::Elf64, Self::Rela) => 24,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RelocationTable {
    pub(crate) range: TargetRange,
    pub(crate) format: RelocationFormat,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelocationAddend {
    Implicit,
    Explicit(i64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RelocationRecord {
    pub(crate) offset: TargetAddress,
    pub(crate) raw_type: u32,
    pub(crate) symbol_index: u32,
    pub(crate) addend: RelocationAddend,
}

impl RelocationRecord {
    pub(crate) fn decode(
        bytes: &[u8],
        class: ElfClass,
        endian: ElfData,
        format: RelocationFormat,
    ) -> LoadResult<Self> {
        let (offset, info, addend) = match class {
            ElfClass::Elf32 => (
                u64::from(read_u32(bytes, 0, endian)?),
                u64::from(read_u32(bytes, 4, endian)?),
                match format {
                    RelocationFormat::Rel => RelocationAddend::Implicit,
                    RelocationFormat::Rela => {
                        RelocationAddend::Explicit(i64::from(read_u32(bytes, 8, endian)? as i32))
                    }
                },
            ),
            ElfClass::Elf64 => (
                read_u64(bytes, 0, endian)?,
                read_u64(bytes, 8, endian)?,
                match format {
                    RelocationFormat::Rel => RelocationAddend::Implicit,
                    RelocationFormat::Rela => {
                        RelocationAddend::Explicit(read_u64(bytes, 16, endian)? as i64)
                    }
                },
            ),
        };
        let (raw_type, symbol_index) = match class {
            ElfClass::Elf32 => ((info & 0xff) as u32, (info >> 8) as u32),
            ElfClass::Elf64 => (info as u32, (info >> 32) as u32),
        };
        Ok(Self {
            offset: TargetAddress::new(offset),
            raw_type,
            symbol_index,
            addend,
        })
    }
}
