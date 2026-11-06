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

//! Cache publication, final segment/RELRO permissions and allocation lifetime.

use super::{
    failure, plan, tags, Allocation, Allocator, Fixture, State, BASE, DYNVA, PROFILES, RELVA,
    TARGET,
};
use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::RelocatedImage,
    memory::{
        AllocationOffset, MemoryMapper, MemoryPermissions, ProtectionLevel, ProtectionRange,
        TargetAddress, TargetRange,
    },
    profile::{ElfClass, LoadLimits, LoadProfile, LoadPurpose},
    CodeCache, ImageMapping, LoadError, LoadResult,
};
use alloc::{rc::Rc, vec, vec::Vec};
use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{DT_NULL, DT_RELA},
    program_header::{PF_R, PF_X, PT_GNU_RELRO},
    reloc::{R_AARCH64_RELATIVE, R_RISCV_RELATIVE},
};

struct Cache {
    state: Rc<State>,
    ranges: Vec<TargetRange>,
    fail_on: Option<usize>,
    own_context: bool,
    initial_protects: usize,
}

impl Cache {
    fn new(state: Rc<State>) -> Self {
        let initial_protects = state.protects.get();
        Self {
            state,
            ranges: Vec::new(),
            fail_on: None,
            own_context: false,
            initial_protects,
        }
    }
}

impl CodeCache for Cache {
    fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
        assert_eq!(self.state.live.get(), 1);
        assert_eq!(self.state.protects.get(), self.initial_protects);
        self.ranges.push(range);
        if self.fail_on == Some(self.ranges.len()) {
            return Err(LoadError::new(
                LoadErrorKind::Backend,
                if self.own_context {
                    ErrorContext::TargetRange {
                        start: TargetAddress::new(0x1234),
                        len: 7,
                        align: 64,
                    }
                } else {
                    ErrorContext::None
                },
            ));
        }
        Ok(())
    }
}

// The flat fixture reads data only and never executes the mapped entry.
struct DataOnlyCache;
impl CodeCache for DataOnlyCache {
    fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
        range.end()?;
        Ok(())
    }
}

fn relocated(
    fixture: &Fixture,
    state: Rc<State>,
    base: u64,
    purpose: LoadPurpose,
) -> RelocatedImage<Allocation> {
    plan(fixture, purpose, LoadLimits::DEFAULT, state.clone())
        .unwrap()
        .allocate(Allocator { state, base })
        .unwrap()
        .map()
        .unwrap()
        .decode()
        .unwrap()
        .relocate()
        .unwrap()
}

fn flags(fixture: &mut Fixture, index: usize, flags: u32) {
    let (base, stride, offset) = match fixture.profile.class() {
        ElfClass::Elf32 => (52, 32, 24),
        ElfClass::Elf64 => (64, 56, 4),
    };
    fixture.number(base + index * stride + offset, u64::from(flags), 4);
}

fn relro(fixture: &mut Fixture, start: u64, len: u64) {
    let (base, stride, count) = match fixture.profile.class() {
        ElfClass::Elf32 => (52, 32, 44),
        ElfClass::Elf64 => (64, 56, 56),
    };
    fixture.bytes[base + 3 * stride..base + 4 * stride].fill(0);
    fixture.number(count, 4, 2);
    fixture.ph(3, 0, u64::from(PT_GNU_RELRO));
    fixture.ph(3, 2, start);
    fixture.ph(3, 4, len);
}

fn permission_updates(state: &State) -> Vec<(u64, u64, MemoryPermissions)> {
    state
        .protection
        .borrow()
        .iter()
        .map(|range| {
            (
                range.allocation_offset().value(),
                range.len(),
                range.permissions(),
            )
        })
        .collect()
}

#[test]
fn sealing_synchronizes_code_without_reapplying_segment_permissions() {
    for profile in PROFILES {
        let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let writes = state.writes.get();
        let mut cache = Cache::new(state.clone());
        let image = image.seal(&mut cache).unwrap();
        assert_eq!(
            cache.ranges,
            [TargetRange::new(TargetAddress::new(0x8000), 0x100)]
        );
        assert_eq!(state.protects.get(), cache.initial_protects);
        assert_eq!(state.writes.get(), writes);
        assert_eq!(state.live.get(), 1);
        assert_eq!(state.drops.get(), 0);
        assert_eq!(image.entry(), Some(TargetAddress::new(0x8000)));
        assert!(image.dynamic().is_some());
        assert!(image.relro().is_none());
        assert_eq!(image.protection_level(), ProtectionLevel::LogicalOnly);
        assert_eq!(
            permission_updates(&state),
            vec![
                (0, 0x1900, MemoryPermissions::NONE),
                (
                    0,
                    0x100,
                    MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE)
                ),
                (
                    0x1000,
                    0x900,
                    MemoryPermissions::READ.bitor(MemoryPermissions::WRITE)
                ),
            ]
        );
        drop(image);
        assert_eq!(state.live.get(), 0);
        assert_eq!(state.drops.get(), 1);
        assert_eq!(state.reader_drops.get(), 1);
    }
}

#[test]
fn sealing_relro_removes_only_write_after_relative_relocation() {
    for profile in PROFILES {
        let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 1);
        dynamic.push((DT_NULL, 0));
        let mut fixture = Fixture::new(profile, &dynamic);
        relro(&mut fixture, TARGET, 16);
        let kind = if profile.machine() == LoadProfile::aarch64().machine() {
            R_AARCH64_RELATIVE
        } else {
            R_RISCV_RELATIVE
        };
        fixture.relocation(RELVA, DT_RELA, TARGET, 0, kind, BASE as i64);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let mut word = [0; 8];
        let width = if profile.class() == ElfClass::Elf32 {
            4
        } else {
            8
        };
        image
            .allocation()
            .read(AllocationOffset::new(TARGET - BASE), &mut word[..width])
            .unwrap();
        assert_eq!(u64::from_le_bytes(word), 0x8000);
        let initial = state.protects.get();
        let image = image.seal(&mut Cache::new(state.clone())).unwrap();
        assert_eq!(
            image.relro(),
            Some(TargetRange::new(TargetAddress::new(TARGET), 16))
        );
        assert_eq!(state.protects.get(), initial + 1);
        assert_eq!(
            permission_updates(&state).last(),
            Some(&(0x1800, 16, MemoryPermissions::READ))
        );
    }
}

#[test]
fn sealing_handles_relro_at_segment_boundaries_and_empty_relro() {
    for profile in PROFILES {
        for (start, len) in [(DYNVA, 0x100), (TARGET, 0x100), (DYNVA, 0x900), (TARGET, 0)] {
            let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
            relro(&mut fixture, start, len);
            let state = Rc::new(State::default());
            let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
            let initial = state.protects.get();
            let image = image.seal(&mut Cache::new(state.clone())).unwrap();
            assert_eq!(
                image.relro(),
                Some(TargetRange::new(TargetAddress::new(start), len))
            );
            assert_eq!(state.protects.get(), initial + usize::from(len != 0));
            if len != 0 {
                assert_eq!(
                    permission_updates(&state).last(),
                    Some(&(start - BASE, len, MemoryPermissions::READ))
                );
            }
        }
    }
}

#[test]
fn mapping_resets_padding_and_holes_before_applying_segment_permissions() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.entry(BASE + 4);
        fixture.ph(0, 1, 0x204);
        fixture.ph(0, 2, BASE + 4);
        fixture.ph(1, 3, 0x8f1);
        fixture.ph(1, 4, 0x8f1);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let mut cache = Cache::new(state.clone());
        let image = image.seal(&mut cache).unwrap();
        assert!(image.relro().is_none());
        assert_eq!(
            permission_updates(&state),
            vec![
                (0, 0x1900, MemoryPermissions::NONE),
                (
                    4,
                    0x100,
                    MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE)
                ),
                (
                    0x1000,
                    0x8f1,
                    MemoryPermissions::READ.bitor(MemoryPermissions::WRITE)
                ),
            ]
        );
        assert_eq!(
            cache.ranges,
            [TargetRange::new(TargetAddress::new(0x8004), 0x100)]
        );
        if usize::BITS == 32 || profile.class() == ElfClass::Elf64 {
            let mapped = plan(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                Rc::new(State::default()),
            )
            .unwrap()
            .allocate(MemoryMapper::new(None))
            .unwrap()
            .map()
            .unwrap();
            for offset in [0, 0x104, 0x18f1] {
                assert_eq!(
                    mapped
                        .allocation()
                        .read(AllocationOffset::new(offset), &mut [0])
                        .unwrap_err()
                        .kind(),
                    LoadErrorKind::PermissionConflict
                );
            }
        }
    }
}

#[test]
fn sealing_synchronizes_every_executable_segment() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        flags(&mut fixture, 1, PF_R | PF_X);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let mut cache = Cache::new(state.clone());
        let image = image.seal(&mut cache).unwrap();
        assert_eq!(
            cache.ranges,
            [
                TargetRange::new(TargetAddress::new(0x8000), 0x100),
                TargetRange::new(TargetAddress::new(0x9000), 0x900)
            ]
        );
        assert_eq!(state.protects.get(), cache.initial_protects);
        drop(image);
    }
}

#[test]
fn sealing_without_executable_segments_preserves_mapped_permissions() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        flags(&mut fixture, 0, PF_R);
        fixture.entry(0);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::SharedObject);
        let mut cache = Cache::new(state.clone());
        let image = image.seal(&mut cache).unwrap();
        assert!(cache.ranges.is_empty());
        assert_eq!(state.protects.get(), cache.initial_protects);
        assert_eq!(image.entry(), None);
    }
}

#[test]
fn sealing_uses_runtime_addresses_for_low_and_full_width_bases() {
    for profile in PROFILES {
        for base in [0, 0x1_0000_8000] {
            if base > u64::from(u32::MAX) && profile.class() == ElfClass::Elf32 {
                continue;
            }
            let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
            let state = Rc::new(State::default());
            let image = relocated(&fixture, state.clone(), base, LoadPurpose::Executable);
            let mut cache = Cache::new(state.clone());
            let image = image.seal(&mut cache).unwrap();
            assert_eq!(cache.ranges[0].start().get(), base);
            assert_eq!(image.entry(), Some(TargetAddress::new(base)));
        }
    }
}

#[test]
fn sealing_rejects_insufficient_protection_before_finalization() {
    for base in PROFILES {
        let profile = base.with_required_protection(ProtectionLevel::HardwareEnforced);
        assert_eq!(
            profile.required_protection(),
            ProtectionLevel::HardwareEnforced
        );
        let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let mut cache = Cache::new(state.clone());
        let error = failure(image.seal(&mut cache));
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        assert_eq!(error.stage(), Some(LoadStage::Seal));
        assert!(matches!(
            error.context(),
            ErrorContext::Protection {
                required: ProtectionLevel::HardwareEnforced,
                provided: ProtectionLevel::LogicalOnly
            }
        ));
        assert!(cache.ranges.is_empty());
        assert_eq!(state.protects.get(), cache.initial_protects);
        assert_eq!(state.live.get(), 0);
        assert_eq!(state.drops.get(), 1);
    }
}

#[test]
fn sealing_accepts_and_reports_hardware_enforcement() {
    for base in PROFILES {
        for required in [
            ProtectionLevel::LogicalOnly,
            ProtectionLevel::HardwareEnforced,
        ] {
            let profile = base.with_required_protection(required);
            let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
            let state = Rc::new(State::default());
            state
                .protection_level
                .set(ProtectionLevel::HardwareEnforced);
            let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable)
                .seal(&mut Cache::new(state))
                .unwrap();
            assert_eq!(image.protection_level(), ProtectionLevel::HardwareEnforced);
        }
    }
}

#[test]
fn sealing_cache_failure_skips_relro_and_drops_the_mapping_once() {
    for profile in PROFILES {
        for fail_on in [1, 2] {
            let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
            flags(&mut fixture, 1, PF_R | PF_X);
            let state = Rc::new(State::default());
            let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
            let mut cache = Cache::new(state.clone());
            cache.fail_on = Some(fail_on);
            let error = failure(image.seal(&mut cache));
            assert_eq!(error.kind(), LoadErrorKind::Backend);
            assert_eq!(error.stage(), Some(LoadStage::Seal));
            let expected = cache.ranges[fail_on - 1];
            assert!(
                matches!(error.context(), ErrorContext::TargetRange { start, len, .. } if *start == expected.start() && *len == expected.len())
            );
            assert_eq!(state.protects.get(), cache.initial_protects);
            assert_eq!(state.live.get(), 0);
            assert_eq!(state.drops.get(), 1);
        }
    }
}

#[test]
fn sealing_preserves_cache_backend_error_context() {
    let fixture = Fixture::new(LoadProfile::riscv64(), &[(DT_NULL, 0)]);
    let state = Rc::new(State::default());
    let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
    let mut cache = Cache::new(state);
    cache.fail_on = Some(1);
    cache.own_context = true;
    let error = failure(image.seal(&mut cache));
    assert!(
        matches!(error.context(), ErrorContext::TargetRange { start, len: 7, align: 64 } if start.get() == 0x1234)
    );
}

#[test]
fn sealing_relro_failure_keeps_cleanup_responsibility() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        relro(&mut fixture, TARGET, 16);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let initial = state.protects.get();
        state.fail_protect.set(Some(initial + 1));
        let mut cache = Cache::new(state.clone());
        let error = failure(image.seal(&mut cache));
        assert_eq!(error.kind(), LoadErrorKind::Backend);
        assert_eq!(error.stage(), Some(LoadStage::Seal));
        assert!(matches!(error.context(), ErrorContext::MemoryAccess {
            allocation_base, offset: 0x1800, len: 16, ..
        } if allocation_base.get() == 0x8000));
        assert_eq!(cache.ranges.len(), 1);
        assert_eq!(state.protects.get(), initial + 1);
        assert_eq!(
            state.protection.borrow().last().unwrap().permissions(),
            MemoryPermissions::READ
        );
        assert_eq!(state.live.get(), 0);
        assert_eq!(state.drops.get(), 1);
    }
}

#[test]
fn mapping_protection_failure_occurs_after_all_copies_and_releases_the_mapping() {
    for profile in PROFILES {
        for (index, offset, len) in [(1, 0, 0x1900), (2, 0, 0x100), (3, 0x1000, 0x900)] {
            let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
            let state = Rc::new(State::default());
            state.fail_protect.set(Some(index));
            let error = failure(
                plan(
                    &fixture,
                    LoadPurpose::Executable,
                    LoadLimits::DEFAULT,
                    state.clone(),
                )
                .unwrap()
                .allocate(Allocator {
                    state: state.clone(),
                    base: 0x8000,
                })
                .unwrap()
                .map(),
            );
            assert_eq!(error.kind(), LoadErrorKind::Backend);
            assert_eq!(error.stage(), Some(LoadStage::Map));
            assert!(matches!(error.context(), ErrorContext::MemoryAccess {
                offset: actual_offset, len: actual_len, ..
            } if *actual_offset == offset && *actual_len == len));
            assert_eq!(state.writes.get(), 6);
            assert_eq!(state.protects.get(), index);
            assert_eq!(state.live.get(), 0);
            assert_eq!(state.drops.get(), 1);
            assert_eq!(state.reader_drops.get(), 1);
        }
    }
}

#[test]
fn mapping_flat_permissions_follow_copy_and_bss_and_allow_data_relocation() {
    let profile = if usize::BITS == 32 {
        LoadProfile::riscv32()
    } else {
        LoadProfile::riscv64()
    };
    let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 1);
    dynamic.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &dynamic);
    fixture.ph(0, 4, 0x180);
    relro(&mut fixture, TARGET, 16);
    fixture.relocation(RELVA, DT_RELA, TARGET, 0, R_RISCV_RELATIVE, BASE as i64);
    let mapped = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        Rc::new(State::default()),
    )
    .unwrap()
    .allocate(MemoryMapper::new(None))
    .unwrap()
    .map()
    .unwrap();
    let mut code = [0; 0x180];
    mapped
        .allocation()
        .read(AllocationOffset::new(0), &mut code)
        .unwrap();
    assert_eq!(&code[..0x100], &[0xa5; 0x100]);
    assert_eq!(&code[0x100..], &[0; 0x80]);
    assert_eq!(
        mapped
            .allocation()
            .read(AllocationOffset::new(0x180), &mut [0])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
    let base = mapped.allocation().base().get();
    let image = mapped
        .decode()
        .unwrap()
        .relocate()
        .unwrap()
        .seal(&mut DataOnlyCache)
        .unwrap();
    let mut word = [0; 8];
    let width = if profile.class() == ElfClass::Elf32 {
        4
    } else {
        8
    };
    image
        .allocation()
        .read(AllocationOffset::new(TARGET - BASE), &mut word[..width])
        .unwrap();
    assert_eq!(u64::from_le_bytes(word), base);
}

#[test]
fn sealing_with_the_flat_backend_enforces_logical_relro_and_holes() {
    let profile = if usize::BITS == 32 {
        LoadProfile::riscv32()
    } else {
        LoadProfile::riscv64()
    };
    let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
    relro(&mut fixture, TARGET, 16);
    let state = Rc::new(State::default());
    let image = plan(
        &fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        state.clone(),
    )
    .unwrap()
    .allocate(MemoryMapper::new(None))
    .unwrap()
    .map()
    .unwrap()
    .decode()
    .unwrap()
    .relocate()
    .unwrap()
    .seal(&mut DataOnlyCache)
    .unwrap();
    assert_eq!(image.protection_level(), ProtectionLevel::LogicalOnly);
    image
        .allocation()
        .read(AllocationOffset::new(TARGET - BASE), &mut [0; 8])
        .unwrap();
    let error = image
        .allocation()
        .read(AllocationOffset::new(0x100), &mut [0; 1])
        .unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
}
