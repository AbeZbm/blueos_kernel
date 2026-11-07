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

//! Complete standalone loading through the crate-root API and host traits.

use super::{
    failure, tags, Allocation, Allocator, Fixture, Input, State, BASE, PROFILES, RELVA, STRVA,
    TARGET,
};
use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage},
    load_elf,
    memory::{AllocationOffset, ImageLayout, ProtectionLevel, TargetAddress, TargetRange},
    profile::{ElfClass, LoadLimits, LoadProfile, LoadPurpose},
    tests::support::{MemoryMapper, SliceElfReader},
    CodeCache, ElfReader, ImageAllocator, ImageMapping, LoadError, LoadRequest, LoadResult,
    LoadedImage,
};
use alloc::{rc::Rc, vec::Vec};
use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{
        DT_FINI, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NEEDED, DT_NULL, DT_RELA, DT_STRSZ,
        DT_STRTAB,
    },
    header::ET_EXEC,
    program_header::PT_NOTE,
    reloc::{R_AARCH64_GLOB_DAT, R_AARCH64_RELATIVE, R_RISCV_JUMP_SLOT, R_RISCV_RELATIVE},
};

struct Cache {
    state: Rc<State>,
    ranges: Vec<TargetRange>,
    fail: bool,
}

impl Cache {
    fn new(state: Rc<State>) -> Self {
        Self {
            state,
            ranges: Vec::new(),
            fail: false,
        }
    }
}

impl CodeCache for Cache {
    fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
        assert_eq!(self.state.live.get(), 1);
        self.ranges.push(range);
        if self.fail {
            return Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None));
        }
        Ok(())
    }
}

fn request(profile: LoadProfile) -> LoadRequest {
    LoadRequest::new(profile, LoadLimits::DEFAULT)
}

fn relative(profile: LoadProfile) -> u32 {
    if profile.machine() == LoadProfile::aarch64().machine() {
        R_AARCH64_RELATIVE
    } else {
        R_RISCV_RELATIVE
    }
}

#[test]
fn standalone_load_finishes_relocation_and_retains_lifecycle_and_backing() {
    const ARRAY: u64 = 0x2600;
    for profile in PROFILES {
        let word = if profile.class() == ElfClass::Elf32 {
            4
        } else {
            8
        };
        let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 2);
        dynamic.extend([
            (DT_INIT, BASE + 8),
            (DT_INIT_ARRAY, ARRAY),
            (DT_INIT_ARRAYSZ, word),
            (DT_FINI, BASE + 0x20),
            (DT_NULL, 0),
        ]);
        let mut fixture = Fixture::new(profile, &dynamic);
        let stride = super::relocation_size(profile.class(), DT_RELA);
        fixture.relocation(
            RELVA,
            DT_RELA,
            TARGET,
            0,
            relative(profile),
            (BASE + 0x30) as i64,
        );
        fixture.relocation(
            RELVA + stride,
            DT_RELA,
            ARRAY,
            0,
            relative(profile),
            (BASE + 0x10) as i64,
        );
        let state = Rc::new(State::default());
        let mut cache = Cache::new(state.clone());
        let image: LoadedImage<Allocation> = load_elf(
            Input {
                fixture: &fixture,
                state: state.clone(),
            },
            request(profile),
            Allocator {
                state: state.clone(),
                base: 0x8000,
            },
            &mut cache,
        )
        .unwrap();
        assert_eq!(image.entry(), Some(TargetAddress::new(0x8000)));
        assert_eq!(image.allocation().base().get(), 0x8000);
        assert_eq!(image.protection_level(), ProtectionLevel::LogicalOnly);
        assert!(image.lifecycle().preinit().is_empty());
        assert_eq!(
            image.lifecycle().init(),
            [TargetAddress::new(0x8008), TargetAddress::new(0x8010)]
        );
        assert_eq!(image.lifecycle().fini(), [TargetAddress::new(0x8020)]);
        let offset = (TARGET - BASE) as usize;
        assert_eq!(
            &image.allocation().bytes[offset..offset + word as usize],
            &0x8030u64.to_le_bytes()[..word as usize]
        );
        assert_eq!(
            cache.ranges,
            [TargetRange::new(TargetAddress::new(0x8000), 0x100)]
        );
        assert_eq!(state.reader_drops.get(), 1);
        assert_eq!(state.live.get(), 1);
        assert_eq!(state.drops.get(), 0);
        drop(image);
        assert_eq!(state.live.get(), 0);
        assert_eq!(state.drops.get(), 1);
    }
}

#[test]
fn standalone_load_borrows_trait_objects_without_retaining_host_services() {
    let profile = LoadProfile::riscv32();
    let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
    let state = Rc::new(State::default());
    let input = Input {
        fixture: &fixture,
        state: state.clone(),
    };
    let mut allocator = Allocator {
        state: state.clone(),
        base: 0x8000,
    };
    let mut cache = Cache::new(state.clone());
    let reader: &dyn ElfReader = &input;
    let memory: &mut dyn ImageAllocator<Allocation = Allocation> = &mut allocator;
    let code_cache: &mut dyn CodeCache = &mut cache;
    let image = load_elf(reader, request(profile), memory, code_cache).unwrap();
    assert_eq!(state.reader_drops.get(), 0);
    drop(input);
    drop(allocator);
    drop(cache);
    assert_eq!(state.reader_drops.get(), 1);
    assert_eq!(state.live.get(), 1);
    assert_eq!(image.entry(), Some(TargetAddress::new(0x8000)));
    drop(image);
    assert_eq!(state.drops.get(), 1);
}

#[test]
fn standalone_load_accepts_a_host_slice_reader() {
    for profile in PROFILES {
        let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let image = load_elf(
            SliceElfReader::new(&fixture.bytes),
            request(profile),
            Allocator {
                state: state.clone(),
                base: 0x8000,
            },
            &mut Cache::new(state.clone()),
        )
        .unwrap();
        assert_eq!(image.entry(), Some(TargetAddress::new(0x8000)));
        assert_eq!(state.reader_drops.get(), 0);
        drop(image);
        assert_eq!(state.drops.get(), 1);
    }
}

#[test]
fn standalone_flat_backend_retains_initialized_bytes_and_denies_holes() {
    // These fixtures exercise byte access only; their entries are never called.
    struct DataOnlyCache;
    impl CodeCache for DataOnlyCache {
        fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
            range.end()?;
            Ok(())
        }
    }
    for profile in PROFILES {
        // A native 64-bit heap may live above the ELF32 address space. The
        // flat backend uses its actual heap address as the target base.
        if usize::BITS > 32 && profile.class() == ElfClass::Elf32 {
            continue;
        }
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.ph(1, 3, 0x500); // Leave a zero-filled BSS tail in the writable segment.
        let image = load_elf(
            SliceElfReader::new(&fixture.bytes),
            request(profile),
            MemoryMapper::new(None),
            &mut DataOnlyCache,
        )
        .unwrap();
        assert_eq!(image.entry(), Some(image.allocation().base()));
        assert_eq!(image.protection_level(), ProtectionLevel::LogicalOnly);
        let mut byte = [0];
        image
            .allocation()
            .read(AllocationOffset::new(0), &mut byte)
            .unwrap();
        assert_eq!(byte, [0xa5]);
        image
            .allocation()
            .read(AllocationOffset::new(TARGET - BASE), &mut byte)
            .unwrap();
        assert_eq!(byte, [0]);
        let error = image
            .allocation()
            .read(AllocationOffset::new(0x100), &mut byte)
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
    }
}

#[test]
fn standalone_load_supports_fixed_exec_without_dynamic_metadata() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.number(16, u64::from(ET_EXEC), 2);
        fixture.ph(2, 0, u64::from(PT_NOTE));
        let state = Rc::new(State::default());
        let mut cache = Cache::new(state.clone());
        let image = load_elf(
            SliceElfReader::new(&fixture.bytes),
            request(profile),
            Allocator {
                state,
                base: 0x8000,
            },
            &mut cache,
        )
        .unwrap();
        assert_eq!(image.entry(), Some(TargetAddress::new(BASE)));
        assert_eq!(image.allocation().base().get(), BASE);
        assert!(image.lifecycle().init().is_empty());
        assert_eq!(
            cache.ranges,
            [TargetRange::new(TargetAddress::new(BASE), 0x100)]
        );
    }
}

#[test]
fn standalone_load_preserves_missing_and_zero_runtime_entries() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_INIT, BASE), (DT_NULL, 0)]);
        fixture.entry(0);
        let state = Rc::new(State::default());
        let image = load_elf(
            SliceElfReader::new(&fixture.bytes),
            request(profile).with_purpose(LoadPurpose::SharedObject),
            Allocator {
                state: state.clone(),
                base: 0x8000,
            },
            &mut Cache::new(state),
        )
        .unwrap();
        assert_eq!(image.entry(), None);
        assert_eq!(image.lifecycle().init(), [TargetAddress::new(0x8000)]);
        drop(image);
        fixture.entry(BASE);
        let state = Rc::new(State::default());
        let image = load_elf(
            SliceElfReader::new(&fixture.bytes),
            request(profile),
            Allocator {
                state: state.clone(),
                base: 0,
            },
            &mut Cache::new(state),
        )
        .unwrap();
        assert_eq!(image.entry(), Some(TargetAddress::new(0)));
        assert_eq!(image.lifecycle().init(), [TargetAddress::new(0)]);
    }
}

#[test]
fn standalone_load_rejects_dependencies_before_allocation() {
    for profile in PROFILES {
        let fixture = Fixture::new(
            profile,
            &[
                (DT_STRTAB, STRVA),
                (DT_STRSZ, super::STRINGS.len() as u64),
                (DT_NEEDED, 1),
                (DT_NULL, 0),
            ],
        );
        for purpose in [LoadPurpose::Executable, LoadPurpose::SharedObject] {
            let state = Rc::new(State::default());
            let mut cache = Cache::new(state.clone());
            let error = failure(load_elf(
                Input {
                    fixture: &fixture,
                    state: state.clone(),
                },
                request(profile).with_purpose(purpose),
                Allocator {
                    state: state.clone(),
                    base: 0x8000,
                },
                &mut cache,
            ));
            assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
            assert_eq!(error.stage(), Some(LoadStage::Plan));
            assert!(matches!(
                error.context(),
                ErrorContext::DynamicTag {
                    tag: DT_NEEDED,
                    value: 1
                }
            ));
            assert_eq!(state.prepares.get(), 0);
            assert_eq!(state.writes.get(), 0);
            assert_eq!(state.reader_drops.get(), 1);
            assert!(cache.ranges.is_empty());
        }
    }
}

#[test]
fn standalone_load_rejects_symbol_relocations_without_cache_publication() {
    for profile in PROFILES {
        let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 1);
        dynamic.push((DT_NULL, 0));
        let mut fixture = Fixture::new(profile, &dynamic);
        let kind = if profile.machine() == LoadProfile::aarch64().machine() {
            R_AARCH64_GLOB_DAT
        } else {
            R_RISCV_JUMP_SLOT
        };
        fixture.relocation(RELVA, DT_RELA, TARGET, 1, kind, 0);
        let state = Rc::new(State::default());
        let mut cache = Cache::new(state.clone());
        let error = failure(load_elf(
            Input {
                fixture: &fixture,
                state: state.clone(),
            },
            request(profile),
            Allocator {
                state: state.clone(),
                base: 0x8000,
            },
            &mut cache,
        ));
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        assert_eq!(error.stage(), Some(LoadStage::Relocate));
        assert!(
            matches!(error.context(), ErrorContext::Relocation { raw_type, symbol_index: 1, .. } if *raw_type == kind)
        );
        assert_eq!(state.reader_drops.get(), 1);
        assert_eq!(state.drops.get(), 1);
        assert_eq!(state.live.get(), 0);
        assert!(cache.ranges.is_empty());
    }
}

#[test]
fn standalone_load_releases_reader_when_header_admission_fails() {
    let profile = LoadProfile::riscv32();
    let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
    fixture.bytes[0] = 0;
    let state = Rc::new(State::default());
    let error = failure(load_elf(
        Input {
            fixture: &fixture,
            state: state.clone(),
        },
        request(profile),
        Allocator {
            state: state.clone(),
            base: 0x8000,
        },
        &mut Cache::new(state.clone()),
    ));
    assert_eq!(error.kind(), LoadErrorKind::BadElf);
    assert_eq!(error.stage(), Some(LoadStage::Admit));
    assert_eq!(state.prepares.get(), 0);
    assert_eq!(state.reader_drops.get(), 1);
    assert_eq!(state.drops.get(), 0);
}

#[test]
fn standalone_load_releases_reader_when_allocation_fails() {
    struct FailingAllocator;
    impl ImageAllocator for FailingAllocator {
        type Allocation = Allocation;
        fn prepare_image(&mut self, _: &ImageLayout) -> LoadResult<Allocation> {
            Err(LoadError::new(LoadErrorKind::Backend, ErrorContext::None))
        }
    }
    let profile = LoadProfile::riscv32();
    let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
    let state = Rc::new(State::default());
    let error = failure(load_elf(
        Input {
            fixture: &fixture,
            state: state.clone(),
        },
        request(profile),
        FailingAllocator,
        &mut Cache::new(state.clone()),
    ));
    assert_eq!(error.stage(), Some(LoadStage::Allocate));
    assert_eq!(state.reader_drops.get(), 1);
    assert_eq!(state.live.get(), 0);
    assert_eq!(state.drops.get(), 0);
}

#[test]
fn standalone_load_releases_mapping_after_partial_copy_failure() {
    let profile = LoadProfile::riscv32();
    let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
    let state = Rc::new(State::default());
    state.fail_write.set(Some(1));
    let mut cache = Cache::new(state.clone());
    let error = failure(load_elf(
        Input {
            fixture: &fixture,
            state: state.clone(),
        },
        request(profile),
        Allocator {
            state: state.clone(),
            base: 0x8000,
        },
        &mut cache,
    ));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(error.stage(), Some(LoadStage::Map));
    assert_eq!(state.reader_drops.get(), 1);
    assert_eq!(state.drops.get(), 1);
    assert_eq!(state.live.get(), 0);
    assert!(cache.ranges.is_empty());
}

#[test]
fn standalone_load_preserves_decode_failure_and_releases_mapping() {
    let profile = LoadProfile::riscv32();
    let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 1);
    dynamic.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &dynamic);
    fixture.relocation(RELVA, DT_RELA, TARGET, 0, relative(profile), BASE as i64);
    let state = Rc::new(State::default());
    state.fail_read.set(Some(1));
    let mut cache = Cache::new(state.clone());
    let error = failure(load_elf(
        Input {
            fixture: &fixture,
            state: state.clone(),
        },
        request(profile),
        Allocator {
            state: state.clone(),
            base: 0x8000,
        },
        &mut cache,
    ));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(error.stage(), Some(LoadStage::Decode));
    assert_eq!(state.drops.get(), 1);
    assert_eq!(state.live.get(), 0);
    assert!(cache.ranges.is_empty());
}

#[test]
fn standalone_load_releases_mapping_after_lifecycle_or_cache_failure() {
    let profile = LoadProfile::riscv32();
    for fail_cache in [false, true] {
        let fixture = Fixture::new(
            profile,
            &[
                (DT_INIT, if fail_cache { BASE } else { BASE + 0x100 }),
                (DT_NULL, 0),
            ],
        );
        let state = Rc::new(State::default());
        let mut cache = Cache::new(state.clone());
        cache.fail = fail_cache;
        let error = failure(load_elf(
            Input {
                fixture: &fixture,
                state: state.clone(),
            },
            request(profile),
            Allocator {
                state: state.clone(),
                base: 0x8000,
            },
            &mut cache,
        ));
        assert_eq!(error.stage(), Some(LoadStage::Seal));
        assert_eq!(
            error.kind(),
            if fail_cache {
                LoadErrorKind::Backend
            } else {
                LoadErrorKind::OutOfBounds
            }
        );
        assert_eq!(cache.ranges.len(), usize::from(fail_cache));
        assert_eq!(state.drops.get(), 1);
        assert_eq!(state.live.get(), 0);
    }
}

#[test]
fn standalone_slice_reader_validates_ranges_without_modifying_failed_reads() {
    let source = SliceElfReader::new(&[1, 2, 3]);
    assert_eq!(ElfReader::len(&source).unwrap(), 3);
    assert!(!ElfReader::is_empty(&source).unwrap());
    let mut destination = [0; 2];
    source.read_exact_at(1, &mut destination).unwrap();
    assert_eq!(destination, [2, 3]);
    source.read_exact_at(3, &mut []).unwrap();
    for offset in [2, 4, u64::MAX] {
        let mut destination = [0xaa; 2];
        let error = source.read_exact_at(offset, &mut destination).unwrap_err();
        assert_eq!(
            error.kind(),
            if offset == u64::MAX {
                LoadErrorKind::IntegerOverflow
            } else {
                LoadErrorKind::OutOfBounds
            }
        );
        assert_eq!(destination, [0xaa; 2]);
        assert!(
            matches!(error.context(), ErrorContext::FileRange {offset: value, len: 2, file_len: 3} if *value == offset)
        );
    }
    assert!(source.read_exact_at(4, &mut []).is_err());
}
