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

//! Minimal ELF headers for loader tests; source adapters live in tests/support.

use crate::memory::TargetAddress;
use alloc::vec::Vec;
use goblin::{
    elf::header::{
        EI_CLASS, EI_DATA, EI_VERSION, ELFCLASS32, ELFCLASS64, ELFDATA2LSB, ELFMAG, EV_CURRENT,
    },
    elf32, elf64,
};

pub struct ElfFixtureBuilder {
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct ProgramHeaderFixture {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: TargetAddress,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeaderFixture {
    pub const fn load() -> Self {
        Self {
            kind: 1,
            flags: 5,
            offset: 0,
            vaddr: TargetAddress::new(0x1000),
            filesz: 4,
            memsz: 0x100,
            align: 4,
        }
    }
}

impl ElfFixtureBuilder {
    pub fn elf64(machine: u16, elf_type: u16) -> Self {
        let mut bytes = alloc::vec![0; elf64::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS64;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, elf_type);
        write_u16(&mut bytes, 18, machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u64(&mut bytes, 32, elf64::header::SIZEOF_EHDR as u64);
        write_u16(&mut bytes, 52, elf64::header::SIZEOF_EHDR as u16);
        write_u16(&mut bytes, 54, elf64::program_header::SIZEOF_PHDR as u16);
        write_u16(&mut bytes, 58, elf64::section_header::SIZEOF_SHDR as u16);

        Self { bytes }
    }

    pub fn elf32(machine: u16, elf_type: u16) -> Self {
        let mut bytes = alloc::vec![0; elf32::header::SIZEOF_EHDR];
        bytes[..4].copy_from_slice(ELFMAG);
        bytes[EI_CLASS] = ELFCLASS32;
        bytes[EI_DATA] = ELFDATA2LSB;
        bytes[EI_VERSION] = EV_CURRENT;

        write_u16(&mut bytes, 16, elf_type);
        write_u16(&mut bytes, 18, machine);
        write_u32(&mut bytes, 20, EV_CURRENT as u32);
        write_u32(&mut bytes, 28, elf32::header::SIZEOF_EHDR as u32); // e_phoff
        write_u16(&mut bytes, 40, elf32::header::SIZEOF_EHDR as u16); // e_ehsize
        write_u16(&mut bytes, 42, elf32::program_header::SIZEOF_PHDR as u16); // e_phentsize
        write_u16(&mut bytes, 46, elf32::section_header::SIZEOF_SHDR as u16); // e_shentsize

        Self { bytes }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        let offset = if self.bytes[EI_CLASS] == ELFCLASS64 {
            48
        } else {
            36
        };
        write_u32(&mut self.bytes, offset, flags);
        self
    }

    pub fn with_entry(mut self, entry: u64) -> Self {
        if self.bytes[EI_CLASS] == ELFCLASS64 {
            write_u64(&mut self.bytes, 24, entry);
        } else {
            write_u32(&mut self.bytes, 24, u32::try_from(entry).unwrap());
        }
        self
    }

    /// Append a program header without padding the segment's file range.
    /// Tests can describe both valid and deliberately truncated segments.
    pub fn with_program_header(mut self, header: ProgramHeaderFixture) -> Self {
        let is64 = self.bytes[EI_CLASS] == ELFCLASS64;
        let count_offset = if is64 { 56 } else { 44 };
        let count = u16::from_le_bytes(
            self.bytes[count_offset..count_offset + 2]
                .try_into()
                .unwrap(),
        );
        let offset = self.bytes.len();
        if is64 {
            self.bytes
                .resize(offset + elf64::program_header::SIZEOF_PHDR, 0);
            write_u32(&mut self.bytes, offset, header.kind);
            write_u32(&mut self.bytes, offset + 4, header.flags);
            for (field, value) in [
                (8, header.offset),
                (16, header.vaddr.get()),
                (32, header.filesz),
                (40, header.memsz),
                (48, header.align),
            ] {
                write_u64(&mut self.bytes, offset + field, value);
            }
        } else {
            self.bytes
                .resize(offset + elf32::program_header::SIZEOF_PHDR, 0);
            write_u32(&mut self.bytes, offset, header.kind);
            for (field, value) in [
                (4, header.offset),
                (8, header.vaddr.get()),
                (16, header.filesz),
                (20, header.memsz),
                (28, header.align),
            ] {
                write_u32(
                    &mut self.bytes,
                    offset + field,
                    u32::try_from(value).unwrap(),
                );
            }
            write_u32(&mut self.bytes, offset + 24, header.flags);
        }
        write_u16(&mut self.bytes, count_offset, count.checked_add(1).unwrap());
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.bytes
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
