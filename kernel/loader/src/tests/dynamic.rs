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

//! Dynamic admission, bounded table scanning and relocation wire decoding.

// Relocation tests reuse the same dynamic ELF fixture and observed mapping.
#[path = "lifecycle.rs"]
mod lifecycle;
#[path = "load.rs"]
mod load;
#[path = "relocation.rs"]
mod relocation;
#[path = "seal.rs"]
mod seal;

use super::fixture::{ElfFixtureBuilder, ProgramHeaderFixture};
use crate::{
    elf::RelocationAddend,
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    image::{DecodedImage, ImageLoader, PlannedImage},
    memory::{
        AllocationOffset, ImageLayout, MemoryPermissions, Placement, ProtectionLevel, TargetAddress,
    },
    profile::{ElfClass, ElfData, LoadLimits, LoadProfile, LoadPurpose},
    tests::support::ProtectionRange,
    ElfReader, ImageAllocator, ImageMapping, LoadError, LoadRequest, LoadResult,
};
use alloc::{rc::Rc, vec, vec::Vec};
use blueos_test_macro::test;
use core::{
    cell::{Cell, RefCell},
    ops::Range,
};
use goblin::elf::{
    dynamic::{
        DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DF_TEXTREL, DT_BIND_NOW, DT_DEBUG, DT_FLAGS, DT_FLAGS_1,
        DT_GNU_HASH, DT_HASH, DT_INIT, DT_JMPREL, DT_NEEDED, DT_NULL, DT_PLTREL, DT_PLTRELSZ,
        DT_REL, DT_RELA, DT_RELAENT, DT_RELASZ, DT_RELENT, DT_RELSZ, DT_RPATH, DT_SONAME, DT_STRSZ,
        DT_STRTAB, DT_SYMENT, DT_SYMTAB,
    },
    header::{EI_DATA, EM_AARCH64, EM_RISCV, ET_DYN, ET_EXEC},
    program_header::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_TLS},
};

const BASE: u64 = 0x1000;
const DATA: usize = 0x300;
const DYNVA: u64 = 0x2000;
const RELVA: u64 = 0x2400;
const STRVA: u64 = 0x2500;
const TARGET: u64 = 0x2800;
const STRINGS: &[u8] = b"\0liba.so\0libb.so\0";
const PROFILES: [LoadProfile; 3] = [
    LoadProfile::riscv32(),
    LoadProfile::riscv64(),
    LoadProfile::aarch64(),
];

struct Fixture {
    bytes: Vec<u8>,
    profile: LoadProfile,
    file_len: u64,
}

impl Fixture {
    fn new(profile: LoadProfile, tags: &[(u64, u64)]) -> Self {
        let class = profile.class();
        let size = match class {
            ElfClass::Elf32 => 8,
            ElfClass::Elf64 => 16,
        };
        let builder = match class {
            ElfClass::Elf32 => ElfFixtureBuilder::elf32(EM_RISCV, ET_DYN),
            ElfClass::Elf64 => ElfFixtureBuilder::elf64(
                if profile.machine() == LoadProfile::aarch64().machine() {
                    EM_AARCH64
                } else {
                    EM_RISCV
                },
                ET_DYN,
            ),
        };
        let mut bytes = builder
            .with_entry(BASE)
            .with_program_header(ProgramHeaderFixture {
                kind: PT_LOAD,
                flags: PF_R | PF_X,
                offset: 0x200,
                vaddr: TargetAddress::new(BASE),
                filesz: 0x100,
                memsz: 0x100,
                align: 16,
            })
            .with_program_header(ProgramHeaderFixture {
                kind: PT_LOAD,
                flags: PF_R | PF_W,
                offset: DATA as u64,
                vaddr: TargetAddress::new(DYNVA),
                filesz: 0x900,
                memsz: 0x900,
                align: 16,
            })
            .with_program_header(ProgramHeaderFixture {
                kind: PT_DYNAMIC,
                flags: PF_R | PF_W,
                offset: DATA as u64,
                vaddr: TargetAddress::new(DYNVA),
                filesz: (tags.len() * size) as u64,
                memsz: (tags.len() * size) as u64,
                align: 4,
            })
            .build();
        if profile.endian() == ElfData::Big {
            let header_fields: &[(usize, usize)] = match class {
                ElfClass::Elf32 => &[
                    (16, 2),
                    (18, 2),
                    (20, 4),
                    (24, 4),
                    (28, 4),
                    (32, 4),
                    (36, 4),
                    (40, 2),
                    (42, 2),
                    (44, 2),
                    (46, 2),
                    (48, 2),
                    (50, 2),
                ],
                ElfClass::Elf64 => &[
                    (16, 2),
                    (18, 2),
                    (20, 4),
                    (24, 8),
                    (32, 8),
                    (40, 8),
                    (48, 4),
                    (52, 2),
                    (54, 2),
                    (56, 2),
                    (58, 2),
                    (60, 2),
                    (62, 2),
                ],
            };
            for &(offset, len) in header_fields {
                bytes[offset..offset + len].reverse();
            }
            let (start, stride, fields): (usize, usize, &[(usize, usize)]) = match class {
                ElfClass::Elf32 => (
                    52,
                    32,
                    &[
                        (0, 4),
                        (4, 4),
                        (8, 4),
                        (12, 4),
                        (16, 4),
                        (20, 4),
                        (24, 4),
                        (28, 4),
                    ],
                ),
                ElfClass::Elf64 => (
                    64,
                    56,
                    &[
                        (0, 4),
                        (4, 4),
                        (8, 8),
                        (16, 8),
                        (24, 8),
                        (32, 8),
                        (40, 8),
                        (48, 8),
                    ],
                ),
            };
            for index in 0..3 {
                for &(offset, len) in fields {
                    let offset = start + index * stride + offset;
                    bytes[offset..offset + len].reverse();
                }
            }
            bytes[EI_DATA] = 2;
        }
        bytes.resize(0xc00, 0xa5);
        let mut fixture = Self {
            file_len: bytes.len() as u64,
            bytes,
            profile,
        };
        for (index, &(tag, value)) in tags.iter().enumerate() {
            fixture.word(DATA + index * size, tag);
            fixture.word(DATA + index * size + size / 2, value);
        }
        let strings = fixture.file_offset(STRVA);
        fixture.bytes[strings..strings + STRINGS.len()].copy_from_slice(STRINGS);
        fixture
    }

    fn word(&mut self, offset: usize, value: u64) {
        let len = match self.profile.class() {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        self.number(offset, value, len);
    }

    fn number(&mut self, offset: usize, value: u64, len: usize) {
        let bytes = match self.profile.endian() {
            ElfData::Little => value.to_le_bytes(),
            ElfData::Big => value.to_be_bytes(),
        };
        let source = if self.profile.endian() == ElfData::Little {
            &bytes[..len]
        } else {
            &bytes[8 - len..]
        };
        self.bytes[offset..offset + len].copy_from_slice(source);
    }

    fn ph(&mut self, index: usize, field: usize, value: u64) {
        // Field numbers follow kind/offset/vaddr/filesz/memsz for both classes.
        let (base, stride, offset, len) = match self.profile.class() {
            ElfClass::Elf32 => (52, 32, [0, 4, 8, 16, 20][field], 4),
            ElfClass::Elf64 => (
                64,
                56,
                [0, 8, 16, 32, 40][field],
                if field == 0 { 4 } else { 8 },
            ),
        };
        self.number(base + index * stride + offset, value, len);
    }

    fn entry(&mut self, value: u64) {
        self.word(24, value);
    }
    fn file_offset(&self, vaddr: u64) -> usize {
        DATA + (vaddr - DYNVA) as usize
    }

    fn relocation(
        &mut self,
        address: u64,
        kind: u64,
        offset: u64,
        symbol: u32,
        raw_type: u32,
        addend: i64,
    ) {
        let file = self.file_offset(address);
        self.word(file, offset);
        let width = match self.profile.class() {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        let info = match self.profile.class() {
            ElfClass::Elf32 => (u64::from(symbol) << 8) | u64::from(raw_type),
            ElfClass::Elf64 => (u64::from(symbol) << 32) | u64::from(raw_type),
        };
        self.word(file + width, info);
        if kind == DT_RELA {
            self.word(file + 2 * width, addend as u64);
        }
    }
}

#[derive(Default)]
struct State {
    dynamic_reads: Cell<usize>,
    reader_drops: Cell<usize>,
    prepares: Cell<usize>,
    reads: Cell<usize>,
    writes: Cell<usize>,
    drops: Cell<usize>,
    live: Cell<usize>,
    fail_read: Cell<Option<usize>>,
    fail_write: Cell<Option<usize>>,
    protection_level: Cell<ProtectionLevel>,
    protects: Cell<usize>,
    protection: RefCell<Vec<ProtectionRange>>,
    fail_protect: Cell<Option<usize>>,
}

#[must_use = "the input retains its read observer"]
struct Input<'a> {
    fixture: &'a Fixture,
    state: Rc<State>,
}
impl ElfReader for Input<'_> {
    fn len(&self) -> LoadResult<u64> {
        Ok(self.fixture.file_len)
    }
    fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> LoadResult<()> {
        if offset >= DATA as u64 {
            self.state
                .dynamic_reads
                .set(self.state.dynamic_reads.get() + 1);
        }
        let end = offset
            .checked_add(dst.len() as u64)
            .filter(|end| *end <= self.fixture.file_len)
            .ok_or_else(|| {
                LoadError::new(
                    LoadErrorKind::Io,
                    ErrorContext::FileRange {
                        offset,
                        len: dst.len() as u64,
                        file_len: self.fixture.file_len,
                    },
                )
            })?;
        dst.fill(0);
        if offset < self.fixture.bytes.len() as u64 {
            let end = end.min(self.fixture.bytes.len() as u64) as usize;
            let len = end - offset as usize;
            dst[..len].copy_from_slice(&self.fixture.bytes[offset as usize..end]);
        }
        Ok(())
    }
}
impl Drop for Input<'_> {
    fn drop(&mut self) {
        self.state
            .reader_drops
            .set(self.state.reader_drops.get() + 1);
    }
}

struct Allocator {
    state: Rc<State>,
    base: u64,
}
#[must_use = "keep test backing alive until the image is discarded"]
struct Allocation {
    state: Rc<State>,
    bytes: Vec<u8>,
    base: TargetAddress,
    align: u64,
}
impl Drop for Allocation {
    fn drop(&mut self) {
        self.state.live.set(self.state.live.get() - 1);
        self.state.drops.set(self.state.drops.get() + 1);
    }
}
impl ImageAllocator for Allocator {
    type Allocation = Allocation;
    fn prepare_image(&mut self, layout: &ImageLayout) -> LoadResult<Self::Allocation> {
        self.state.prepares.set(self.state.prepares.get() + 1);
        self.state.live.set(self.state.live.get() + 1);
        Ok(Allocation {
            state: self.state.clone(),
            bytes: vec![0; layout.size() as usize],
            base: match layout.placement() {
                Placement::Anywhere => TargetAddress::new(self.base),
                Placement::Fixed(range) => range.start(),
            },
            align: layout.align(),
        })
    }
}
impl Allocation {
    fn range(&self, offset: AllocationOffset, len: usize) -> LoadResult<Range<usize>> {
        let end = offset
            .value()
            .checked_add(len as u64)
            .filter(|end| *end <= self.bytes.len() as u64)
            .ok_or_else(|| LoadError::new(LoadErrorKind::OutOfBounds, ErrorContext::None))?;
        Ok(offset.value() as usize..end as usize)
    }
}
impl ImageMapping for Allocation {
    fn protection_level(&self) -> ProtectionLevel {
        self.state.protection_level.get()
    }

    fn set_permissions(
        &mut self,
        offset: AllocationOffset,
        len: u64,
        permissions: MemoryPermissions,
    ) -> LoadResult<()> {
        self.state.protects.set(self.state.protects.get() + 1);
        self.state
            .protection
            .borrow_mut()
            .push(ProtectionRange::new(offset, len, permissions));
        if self.state.fail_protect.get() == Some(self.state.protects.get()) {
            return Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None));
        }
        Ok(())
    }

    fn base(&self) -> TargetAddress {
        self.base
    }
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn align(&self) -> u64 {
        self.align
    }
    fn read(&self, offset: AllocationOffset, dst: &mut [u8]) -> LoadResult<()> {
        self.state.reads.set(self.state.reads.get() + 1);
        if self.state.fail_read.get() == Some(self.state.reads.get()) {
            dst.fill(0xff);
            return Err(LoadError::new(
                LoadErrorKind::Io,
                ErrorContext::DynamicTag {
                    tag: DT_REL,
                    value: offset.value(),
                },
            ));
        }
        dst.copy_from_slice(&self.bytes[self.range(offset, dst.len())?]);
        Ok(())
    }
    fn write(&mut self, offset: AllocationOffset, src: &[u8]) -> LoadResult<()> {
        let range = self.range(offset, src.len())?;
        self.bytes[range].copy_from_slice(src);
        self.state.writes.set(self.state.writes.get() + 1);
        if self.state.fail_write.get() == Some(self.state.writes.get()) {
            return Err(LoadError::new(LoadErrorKind::Io, ErrorContext::None));
        }
        Ok(())
    }
    fn zero(&mut self, offset: AllocationOffset, len: u64) -> LoadResult<()> {
        let len = usize::try_from(len)
            .map_err(|_| LoadError::new(LoadErrorKind::OutOfBounds, ErrorContext::None))?;
        let range = self.range(offset, len)?;
        self.bytes[range].fill(0);
        Ok(())
    }
}

fn request(profile: LoadProfile, purpose: LoadPurpose, limits: LoadLimits) -> LoadRequest {
    LoadRequest::new(profile, limits).with_purpose(purpose)
}
fn plan<'a>(
    fixture: &'a Fixture,
    purpose: LoadPurpose,
    limits: LoadLimits,
    state: Rc<State>,
) -> LoadResult<PlannedImage<Input<'a>>> {
    ImageLoader::new(
        Input { fixture, state },
        request(fixture.profile, purpose, limits),
    )
    .admit()?
    .inspect()?
    .plan()
}
fn load(
    fixture: &Fixture,
    purpose: LoadPurpose,
    limits: LoadLimits,
    state: Rc<State>,
) -> LoadResult<DecodedImage<Allocation>> {
    plan(fixture, purpose, limits, state.clone())?
        .allocate(Allocator {
            state,
            base: 0x8000,
        })?
        .map()?
        .decode()
}
fn failure<T>(result: LoadResult<T>) -> LoadError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("invalid dynamic image accepted"),
    }
}
fn relocation_size(class: ElfClass, kind: u64) -> u64 {
    match (class, kind) {
        (ElfClass::Elf32, DT_REL) => 8,
        (ElfClass::Elf32, _) => 12,
        (ElfClass::Elf64, DT_REL) => 16,
        (ElfClass::Elf64, _) => 24,
    }
}
fn tags(class: ElfClass, kind: u64, address: u64, count: u64) -> Vec<(u64, u64)> {
    let size = relocation_size(class, kind);
    let (length, entry) = if kind == DT_REL {
        (DT_RELSZ, DT_RELENT)
    } else {
        (DT_RELASZ, DT_RELAENT)
    };
    vec![(kind, address), (length, count * size), (entry, size)]
}

#[test]
fn dynamic_decodes_rel_and_rela_for_both_classes_and_byte_orders() {
    for base in PROFILES {
        for endian in [ElfData::Little, ElfData::Big] {
            let profile = LoadProfile::new(
                base.class(),
                endian,
                base.machine(),
                base.header_flags(),
                base.entry_mode(),
            );
            for kind in [DT_REL, DT_RELA] {
                let mut dynamic = tags(profile.class(), kind, RELVA, 2);
                dynamic.push((DT_NULL, 0));
                let mut fixture = Fixture::new(profile, &dynamic);
                let size = relocation_size(profile.class(), kind);
                let raw_type = if profile.class() == ElfClass::Elf32 {
                    3
                } else {
                    0x12345678
                };
                let minimum_addend = if profile.class() == ElfClass::Elf32 {
                    i64::from(i32::MIN)
                } else {
                    i64::MIN
                };
                fixture.relocation(RELVA, kind, TARGET, 7, raw_type, -17);
                fixture.relocation(RELVA + size, kind, TARGET + 8, 0, 2, minimum_addend);
                let state = Rc::new(State::default());
                let image = load(
                    &fixture,
                    LoadPurpose::Executable,
                    LoadLimits::DEFAULT,
                    state.clone(),
                )
                .unwrap();
                assert_eq!(image.entry().unwrap().get(), 0x8000);
                assert_eq!(state.reader_drops.get(), 1);
                assert_eq!(image.relocations().len(), 2);
                assert_eq!(image.relocations()[0].offset.get(), TARGET);
                assert_eq!(image.relocations()[0].symbol_index, 7);
                assert_eq!(image.relocations()[0].raw_type, raw_type);
                assert_eq!(
                    image.relocations()[0].addend,
                    if kind == DT_REL {
                        RelocationAddend::Implicit
                    } else {
                        RelocationAddend::Explicit(-17)
                    }
                );
                assert_eq!(
                    image.relocations()[1].addend,
                    if kind == DT_REL {
                        RelocationAddend::Implicit
                    } else {
                        RelocationAddend::Explicit(minimum_addend)
                    }
                );
                let mut untouched = [0; 8];
                image
                    .allocation()
                    .read(AllocationOffset::new(TARGET - BASE), &mut untouched)
                    .unwrap();
                assert_eq!(untouched, [0xa5; 8]); // Decoding does not apply relocation writes.
                assert_eq!(state.live.get(), 1);
                assert_eq!(state.drops.get(), 0);
                drop(image);
                assert_eq!(state.drops.get(), 1);
                assert_eq!(state.live.get(), 0);
            }
        }
    }
}

#[test]
fn shared_objects_accept_no_entry_and_no_soname_but_require_dynamic() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.entry(0);
        let state = Rc::new(State::default());
        let image = load(
            &fixture,
            LoadPurpose::SharedObject,
            LoadLimits::DEFAULT,
            state.clone(),
        )
        .unwrap();
        assert_eq!(image.entry(), None);
        assert!(image.dynamic().unwrap().value(DT_SONAME).is_none());
        drop(image);
        assert_eq!(
            failure(plan(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                state.clone()
            ))
            .kind(),
            LoadErrorKind::BadElf
        );
        fixture.ph(2, 0, 0);
        assert_eq!(
            failure(plan(
                &fixture,
                LoadPurpose::SharedObject,
                LoadLimits::DEFAULT,
                state
            ))
            .kind(),
            LoadErrorKind::BadElf
        );
    }
}

#[test]
fn shared_objects_reject_exec_pie_and_invalid_nonzero_entries() {
    for profile in PROFILES {
        for case in 0..3 {
            let mut fixture = Fixture::new(
                profile,
                &[
                    (DT_FLAGS_1, if case == 1 { DF_1_PIE } else { 0 }),
                    (DT_NULL, 0),
                ],
            );
            if case == 0 {
                fixture.number(16, ET_EXEC as u64, 2);
            }
            if case == 2 {
                fixture.entry(BASE + 1);
            }
            let state = Rc::new(State::default());
            let error = failure(plan(
                &fixture,
                LoadPurpose::SharedObject,
                LoadLimits::DEFAULT,
                state.clone(),
            ));
            assert_eq!(error.stage(), Some(LoadStage::Plan));
            assert_eq!(
                error.kind(),
                if case == 2 {
                    LoadErrorKind::InvalidAlignment
                } else {
                    LoadErrorKind::UnsupportedByProfile
                }
            );
            if case == 1 {
                assert!(matches!(
                    error.context(),
                    ErrorContext::DynamicTag { tag: DT_FLAGS_1, value }
                        if *value == DF_1_PIE
                ));
            }
            assert_eq!(state.prepares.get(), 0);
        }
    }
}

#[test]
fn runtime_zero_entry_remains_distinct_from_a_missing_dso_entry() {
    let fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_NULL, 0)]);
    let state = Rc::new(State::default());
    let image = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        state.clone(),
    )
    .unwrap()
    .allocate(Allocator { state, base: 0 })
    .unwrap()
    .map()
    .unwrap()
    .decode()
    .unwrap();
    assert_eq!(image.entry(), Some(TargetAddress::new(0)));
}

#[test]
fn dynamic_preserves_needed_order_and_unresolved_metadata() {
    let fixture = Fixture::new(
        LoadProfile::riscv32(),
        &[
            (DT_NEEDED, 9),
            (DT_STRTAB, STRVA),
            (DT_STRSZ, STRINGS.len() as u64),
            (DT_NEEDED, 1),
            (DT_NEEDED, 9),
            (DT_SONAME, 1),
            (DT_INIT, BASE),
            (DT_NULL, 0),
        ],
    );
    let image = load(
        &fixture,
        LoadPurpose::SharedObject,
        LoadLimits::DEFAULT,
        Rc::new(State::default()),
    )
    .unwrap();
    let info = image.dynamic().unwrap();
    assert_eq!(info.needed().collect::<Vec<_>>(), [9, 1, 9]);
    assert_eq!(info.value(DT_SONAME), Some(1));
    assert_eq!(info.value(DT_INIT), Some(BASE));
}

#[test]
fn dynamic_rejects_unsupported_tags_and_flags_before_allocation() {
    for (tag, value) in [
        (DT_RPATH, 1),
        (0x12345678, 0),
        (DT_FLAGS, DF_TEXTREL),
        (DT_FLAGS_1, 0x80000000),
    ] {
        let fixture = Fixture::new(LoadProfile::riscv32(), &[(tag, value), (DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let error = failure(load(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            state.clone(),
        ));
        assert_eq!(error.stage(), Some(LoadStage::Plan));
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        assert!(
            matches!(error.context(),ErrorContext::DynamicTag {tag: actual,value: actual_value} if *actual==tag && *actual_value==value)
        );
        assert_eq!(state.prepares.get(), 0);
        assert_eq!(state.writes.get(), 0);
        assert_eq!(state.reader_drops.get(), 1);
    }
}

#[test]
fn dynamic_rejects_native_tls_and_interpreters_even_with_extended_header_policy() {
    for kind in [PT_TLS, PT_INTERP] {
        let base = LoadProfile::riscv32();
        let profile = base.with_additional_program_headers(&[PT_TLS, PT_INTERP]);
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.ph(2, 0, kind as u64);
        let state = Rc::new(State::default());
        let error = failure(plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            state.clone(),
        ));
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        assert_eq!(error.stage(), Some(LoadStage::Plan));
        assert_eq!(state.prepares.get(), 0);
        assert_eq!(state.writes.get(), 0);
    }
}

#[test]
fn dynamic_requires_termination_and_complete_entries() {
    for case in 0..3 {
        let mut fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_DEBUG, 0)]);
        if case == 1 {
            fixture.ph(2, 3, 0);
        }
        if case == 2 {
            fixture.ph(2, 3, 7);
        }
        let error = failure(plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            Rc::new(State::default()),
        ));
        assert_eq!(error.kind(), LoadErrorKind::BadElf);
        assert_eq!(error.stage(), Some(LoadStage::Plan));
        match case {
            0 => assert!(matches!(
                error.context(),
                ErrorContext::DynamicTag {
                    tag: DT_NULL,
                    value: 8
                }
            )),
            _ => assert!(matches!(
                error.context(),
                ErrorContext::TargetRange { start, len, .. }
                    if start.get() == DYNVA && *len == if case == 1 { 0 } else { 7 }
            )),
        }
    }
}

#[test]
fn dynamic_rejects_duplicate_singletons_including_zero_values() {
    for tag in [DT_DEBUG, DT_FLAGS, DT_BIND_NOW] {
        let fixture = Fixture::new(LoadProfile::riscv32(), &[(tag, 0), (tag, 0), (DT_NULL, 0)]);
        assert_eq!(
            failure(plan(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                Rc::new(State::default())
            ))
            .kind(),
            LoadErrorKind::BadElf
        );
    }
}

#[test]
fn dynamic_must_match_a_file_backed_load_segment() {
    for case in 0..3 {
        let mut fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_NULL, 0)]);
        match case {
            0 => fixture.ph(2, 1, DATA as u64 + 8),
            1 => fixture.ph(1, 3, 0),
            _ => fixture.ph(2, 2, 0x1800),
        }
        let state = Rc::new(State::default());
        let error = failure(load(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            state.clone(),
        ));
        assert_eq!(error.kind(), LoadErrorKind::BadElf);
        assert_eq!(error.stage(), Some(LoadStage::Plan));
        assert!(matches!(
            error.context(),
            ErrorContext::TargetRange { start, len: 8, .. }
                if start.get() == if case == 2 { 0x1800 } else { DYNVA }
        ));
        assert_eq!(state.prepares.get(), 0);
    }
}

#[test]
fn dynamic_range_errors_identify_the_pointer_tag() {
    let address = 0x1800;
    for profile in PROFILES {
        let symbol_size = if profile.class() == ElfClass::Elf32 {
            16
        } else {
            24
        };
        for (tag, mut dynamic) in [
            (DT_STRTAB, vec![(DT_STRTAB, address), (DT_STRSZ, 16)]),
            (
                DT_SYMTAB,
                vec![(DT_SYMTAB, address), (DT_SYMENT, symbol_size)],
            ),
            (DT_HASH, vec![(DT_HASH, address)]),
            (DT_GNU_HASH, vec![(DT_GNU_HASH, address)]),
            (DT_REL, tags(profile.class(), DT_REL, address, 1)),
            (DT_RELA, tags(profile.class(), DT_RELA, address, 1)),
            (
                DT_JMPREL,
                vec![
                    (DT_JMPREL, address),
                    (DT_PLTRELSZ, relocation_size(profile.class(), DT_REL)),
                    (DT_PLTREL, DT_REL),
                    (DT_BIND_NOW, 0),
                ],
            ),
            (
                DT_JMPREL,
                vec![
                    (DT_JMPREL, address),
                    (DT_PLTRELSZ, relocation_size(profile.class(), DT_RELA)),
                    (DT_PLTREL, DT_RELA),
                    (DT_BIND_NOW, 0),
                ],
            ),
        ] {
            dynamic.push((DT_NULL, 0));
            let fixture = Fixture::new(profile, &dynamic);
            let state = Rc::new(State::default());
            let error = failure(load(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                state.clone(),
            ));
            assert_eq!(error.kind(), LoadErrorKind::BadElf);
            assert_eq!(error.stage(), Some(LoadStage::Plan));
            assert!(matches!(
                error.context(),
                ErrorContext::DynamicTag { tag: actual, value }
                    if *actual == tag && *value == address
            ));
            assert_eq!(state.prepares.get(), 0);
        }
    }
}

#[test]
fn overlapping_relocation_errors_identify_the_declaring_tag() {
    for profile in PROFILES {
        let mut dynamic = tags(profile.class(), DT_REL, RELVA, 2);
        dynamic.extend(tags(profile.class(), DT_RELA, RELVA, 1));
        dynamic.push((DT_NULL, 0));
        let fixture = Fixture::new(profile, &dynamic);
        let error = failure(plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            Rc::new(State::default()),
        ));
        assert!(matches!(
            error.context(),
            ErrorContext::DynamicTag {
                tag: DT_RELA,
                value: RELVA
            }
        ));

        // The PLT range overlaps a valid main table but extends past the
        // file-backed segment. Diagnose its original pointer before merging.
        for format in [DT_REL, DT_RELA] {
            let size = relocation_size(profile.class(), format);
            let main = DYNVA + 0x900 - 4 * size;
            let plt = main + size;
            let mut dynamic = tags(profile.class(), format, main, 2);
            dynamic.extend([
                (DT_JMPREL, plt),
                (DT_PLTRELSZ, 4 * size),
                (DT_PLTREL, format),
                (DT_BIND_NOW, 0),
                (DT_NULL, 0),
            ]);
            let fixture = Fixture::new(profile, &dynamic);
            let state = Rc::new(State::default());
            let error = failure(load(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                state.clone(),
            ));
            assert_eq!(error.kind(), LoadErrorKind::BadElf);
            assert_eq!(error.stage(), Some(LoadStage::Plan));
            assert!(matches!(
                error.context(),
                ErrorContext::DynamicTag { tag: DT_JMPREL, value } if *value == plt
            ));
            assert_eq!(state.prepares.get(), 0);
        }
    }
}

#[test]
fn dynamic_padding_and_post_null_garbage_do_not_drive_reads_or_allocations() {
    let mut fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_NULL, 0), (DT_RPATH, 1)]);
    fixture.file_len = 64 * 1024 * 1024 - 0x1000;
    fixture.ph(1, 3, fixture.file_len - DATA as u64);
    fixture.ph(1, 4, fixture.file_len - DATA as u64);
    fixture.ph(2, 3, fixture.file_len - DATA as u64);
    fixture.ph(2, 4, fixture.file_len - DATA as u64);
    let state = Rc::new(State::default());
    drop(
        plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT.with_max_dynamic_entries(1),
            state.clone(),
        )
        .unwrap(),
    );
    assert_eq!(state.dynamic_reads.get(), 1);
    assert_eq!(state.prepares.get(), 0);
}

#[test]
fn dynamic_entry_budget_is_checked_before_the_next_read() {
    for maximum in [0, 1] {
        let fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_DEBUG, 0), (DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let error = failure(plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT.with_max_dynamic_entries(maximum),
            state.clone(),
        ));
        assert!(
            matches!(error.context(),ErrorContext::Limit {resource:LimitKind::DynamicEntryCount,actual,maximum: bound} if *actual==maximum+1 && *bound==maximum)
        );
        assert_eq!(state.dynamic_reads.get(), maximum as usize);
    }
}

#[test]
fn relocation_tables_require_complete_geometry_and_file_backing() {
    let size = 8;
    for dynamic in [
        vec![(DT_REL, RELVA)],
        vec![(DT_RELSZ, size)],
        vec![(DT_REL, RELVA), (DT_RELSZ, size), (DT_RELENT, 0)],
        vec![(DT_REL, RELVA), (DT_RELSZ, 7), (DT_RELENT, size)],
        vec![(DT_REL, 0x1800), (DT_RELSZ, size), (DT_RELENT, size)],
        vec![(DT_REL, 0x28fc), (DT_RELSZ, size), (DT_RELENT, size)],
    ] {
        let mut dynamic = dynamic;
        dynamic.push((DT_NULL, 0));
        let fixture = Fixture::new(LoadProfile::riscv32(), &dynamic);
        let state = Rc::new(State::default());
        assert_eq!(
            failure(load(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                state.clone()
            ))
            .kind(),
            LoadErrorKind::BadElf
        );
        assert_eq!(state.prepares.get(), 0);
    }
}

#[test]
fn relocation_budget_counts_all_tables_before_allocation() {
    let profile = LoadProfile::riscv32();
    let mut dynamic = tags(profile.class(), DT_REL, RELVA, 1);
    dynamic.extend(tags(profile.class(), DT_RELA, RELVA + 0x100, 1));
    dynamic.push((DT_NULL, 0));
    let fixture = Fixture::new(profile, &dynamic);
    let state = Rc::new(State::default());
    let error = failure(load(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT.with_max_relocations(1),
        state.clone(),
    ));
    assert!(matches!(
        error.context(),
        ErrorContext::Limit {
            resource: LimitKind::RelocationCount,
            actual: 2,
            maximum: 1
        }
    ));
    assert_eq!(state.prepares.get(), 0);
}

#[test]
fn empty_relocation_tables_do_not_require_a_backed_address() {
    let fixture = Fixture::new(
        LoadProfile::riscv64(),
        &[(DT_REL, 0), (DT_RELSZ, 0), (DT_RELENT, 16), (DT_NULL, 0)],
    );
    let image = load(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT.with_max_relocations(0),
        Rc::new(State::default()),
    )
    .unwrap();
    assert!(image.relocations().is_empty());
}

#[test]
fn plt_relocations_require_eager_binding_and_derive_their_entry_size() {
    for profile in PROFILES {
        for kind in [DT_REL, DT_RELA] {
            for binding in [
                None,
                Some((DT_BIND_NOW, 0)),
                Some((DT_FLAGS, DF_BIND_NOW)),
                Some((DT_FLAGS_1, DF_1_NOW)),
            ] {
                let mut dynamic = vec![
                    (DT_JMPREL, RELVA),
                    (DT_PLTRELSZ, relocation_size(profile.class(), kind)),
                    (DT_PLTREL, kind),
                ];
                dynamic.extend(binding);
                dynamic.push((DT_NULL, 0));
                let mut fixture = Fixture::new(profile, &dynamic);
                fixture.relocation(RELVA, kind, TARGET, 0, 2, -1);
                let state = Rc::new(State::default());
                let result = load(
                    &fixture,
                    LoadPurpose::Executable,
                    LoadLimits::DEFAULT,
                    state.clone(),
                );
                if binding.is_some() {
                    assert_eq!(result.unwrap().relocations().len(), 1);
                } else {
                    let error = failure(result);
                    assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
                    assert_eq!(error.stage(), Some(LoadStage::Plan));
                    assert!(matches!(
                        error.context(),
                        ErrorContext::DynamicTag {
                            tag: DT_JMPREL,
                            value: RELVA
                        }
                    ));
                    assert_eq!(state.prepares.get(), 0);
                    assert_eq!(state.writes.get(), 0);
                }
            }
        }
    }
}

#[test]
fn plt_overlap_is_decoded_once_and_misaligned_overlap_is_rejected() {
    let profile = LoadProfile::riscv32();
    for displacement in [0, 8, 1] {
        let mut dynamic = tags(profile.class(), DT_REL, RELVA, 2);
        dynamic.extend([
            (DT_JMPREL, RELVA + displacement),
            (DT_PLTRELSZ, 8),
            (DT_PLTREL, DT_REL),
            (DT_BIND_NOW, 0),
            (DT_NULL, 0),
        ]);
        let mut fixture = Fixture::new(profile, &dynamic);
        fixture.relocation(RELVA, DT_REL, TARGET, 0, 2, 0);
        fixture.relocation(RELVA + 8, DT_REL, TARGET + 4, 0, 2, 0);
        let result = load(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT.with_max_relocations(2),
            Rc::new(State::default()),
        );
        if displacement == 1 {
            assert_eq!(failure(result).kind(), LoadErrorKind::BadElf);
        } else {
            assert_eq!(result.unwrap().relocations().len(), 2);
        }
    }
}

#[test]
fn dynamic_checks_metadata_pairs_sizes_and_minimum_table_ranges() {
    for profile in PROFILES {
        for dynamic in [
            vec![(DT_STRTAB, STRVA)],
            vec![(DT_STRSZ, 17)],
            vec![(DT_NEEDED, 0)],
            vec![(DT_SONAME, 17), (DT_STRTAB, STRVA), (DT_STRSZ, 17)],
            vec![
                (DT_SYMTAB, 0x1800),
                (
                    DT_SYMENT,
                    if profile.class() == ElfClass::Elf32 {
                        16
                    } else {
                        24
                    },
                ),
            ],
            vec![(DT_SYMTAB, 0x2600), (DT_SYMENT, 1)],
            vec![(DT_HASH, 0x28fc)],
            vec![(DT_GNU_HASH, 0x28fc)],
        ] {
            let mut dynamic = dynamic;
            dynamic.push((DT_NULL, 0));
            let fixture = Fixture::new(profile, &dynamic);
            assert_eq!(
                failure(plan(
                    &fixture,
                    LoadPurpose::Executable,
                    LoadLimits::DEFAULT,
                    Rc::new(State::default())
                ))
                .kind(),
                LoadErrorKind::BadElf
            );
        }
    }
}

#[test]
fn decoding_read_failure_preserves_context_and_drops_the_allocation_once() {
    let profile = LoadProfile::riscv32();
    let mut dynamic = tags(profile.class(), DT_REL, RELVA, 2);
    dynamic.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &dynamic);
    fixture.relocation(RELVA, DT_REL, TARGET, 0, 2, 0);
    fixture.relocation(RELVA + 8, DT_REL, TARGET + 4, 0, 2, 0);
    let state = Rc::new(State::default());
    state.fail_read.set(Some(2));
    let error = failure(load(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        state.clone(),
    ));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(error.stage(), Some(LoadStage::Decode));
    assert!(matches!(
        error.context(),
        ErrorContext::DynamicTag {
            tag: DT_REL,
            value: 0x1408
        }
    ));
    assert_eq!(state.drops.get(), 1);
    assert_eq!(state.live.get(), 0);
    assert_eq!(state.reader_drops.get(), 1);
}

#[test]
fn static_images_decode_without_dynamic_metadata() {
    let mut fixture = Fixture::new(LoadProfile::riscv32(), &[(DT_NULL, 0)]);
    fixture.ph(2, 0, 0);
    let image = load(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::new(State::default()),
    )
    .unwrap();
    assert!(image.dynamic().is_none());
    assert!(image.relocations().is_empty());
}
