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

//! Single-image relative relocation and cleanup through the mapping backend.

use super::{
    failure, load, plan, relocation_size, tags, Allocation, Allocator, Fixture, State, BASE,
    PROFILES, RELVA, TARGET,
};
use crate::{
    error::{ErrorContext, LoadErrorKind, LoadStage},
    image::DecodedImage,
    memory::{AllocationOffset, TargetAddress},
    profile::{ElfClass, ElfData, ElfMachine, LoadLimits, LoadProfile, LoadPurpose},
    ImageMapping,
};
use alloc::rc::Rc;
use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{DT_NULL, DT_REL, DT_RELA},
    program_header::PT_NOTE,
    reloc::{R_AARCH64_RELATIVE, R_RISCV_RELATIVE},
};

fn relative_type(profile: LoadProfile) -> u32 {
    match profile.machine() {
        ElfMachine::Riscv => R_RISCV_RELATIVE,
        ElfMachine::Aarch64 => R_AARCH64_RELATIVE,
        _ => panic!("unsupported test profile"),
    }
}

fn fixture(profile: LoadProfile, kind: u64, count: u64) -> Fixture {
    let mut dynamic = tags(profile.class(), kind, RELVA, count);
    dynamic.push((DT_NULL, 0));
    let mut fixture = Fixture::new(profile, &dynamic);
    let size = relocation_size(profile.class(), kind);
    for index in 0..count {
        fixture.relocation(
            RELVA + index * size,
            kind,
            TARGET + index * 8,
            0,
            relative_type(profile),
            (BASE + index * 8) as i64,
        );
    }
    fixture
}

fn decode(fixture: &Fixture, state: Rc<State>, base: u64) -> DecodedImage<Allocation> {
    let image = plan(
        fixture,
        LoadPurpose::Executable,
        LoadLimits::DEFAULT,
        state.clone(),
    )
    .unwrap()
    .allocate(Allocator {
        state: state.clone(),
        base,
    })
    .unwrap()
    .map()
    .unwrap()
    .decode()
    .unwrap();
    state.writes.set(0);
    image
}

fn value(allocation: &impl ImageMapping, profile: LoadProfile, target: u64) -> u64 {
    let mut bytes = [0; 8];
    let width = if profile.class() == ElfClass::Elf32 {
        4
    } else {
        8
    };
    allocation
        .read(AllocationOffset::new(target - BASE), &mut bytes[..width])
        .unwrap();
    match (profile.class(), profile.endian()) {
        (ElfClass::Elf32, ElfData::Little) => {
            u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
        }
        (ElfClass::Elf32, ElfData::Big) => {
            u64::from(u32::from_be_bytes(bytes[..4].try_into().unwrap()))
        }
        (ElfClass::Elf64, ElfData::Little) => u64::from_le_bytes(bytes),
        (ElfClass::Elf64, ElfData::Big) => u64::from_be_bytes(bytes),
    }
}

fn rejects(fixture: &Fixture, base: u64, expected: LoadErrorKind, target: u64) {
    let state = Rc::new(State::default());
    let image = decode(fixture, state.clone(), base);
    let error = failure(image.relocate());
    assert_eq!(error.stage(), Some(LoadStage::Relocate));
    assert_eq!(error.kind(), expected);
    assert!(
        matches!(error.context(), ErrorContext::Relocation { target: actual, .. }
        if actual.get() == target)
    );
    assert_eq!(state.writes.get(), 0);
    assert_eq!(state.live.get(), 0);
    assert_eq!(state.drops.get(), 1);
    assert_eq!(state.reader_drops.get(), 1);
}

#[test]
fn relative_relocation_supports_all_profiles_and_byte_orders() {
    for base in PROFILES {
        for endian in [ElfData::Little, ElfData::Big] {
            let profile = LoadProfile::new(
                base.class(),
                endian,
                base.machine(),
                base.header_flags(),
                base.entry_mode(),
            );
            let fixture = fixture(profile, DT_RELA, 2);
            let state = Rc::new(State::default());
            let decoded = decode(&fixture, state.clone(), 0x8000);
            let reads = state.reads.get();
            let image = decoded.relocate().unwrap();
            assert_eq!(state.reads.get(), reads);
            assert_eq!(state.writes.get(), 2);
            assert_eq!(state.live.get(), 1);
            assert_eq!(state.drops.get(), 0);
            assert_eq!(image.entry(), Some(TargetAddress::new(0x8000)));
            assert!(image.dynamic().is_some());
            assert_eq!(image.relocations().len(), 2);
            assert_eq!(value(image.allocation(), profile, TARGET), 0x8000);
            assert_eq!(value(image.allocation(), profile, TARGET + 8), 0x8008);
            drop(image);
            assert_eq!(state.live.get(), 0);
            assert_eq!(state.drops.get(), 1);
        }
    }
}

#[test]
fn relative_relocation_handles_negative_bias_and_signed_addends() {
    for profile in PROFILES {
        for (base, addend, expected) in [(0, TARGET as i64, TARGET - BASE), (0x8000, -16, 0x6ff0)] {
            let mut fixture = fixture(profile, DT_RELA, 1);
            fixture.relocation(RELVA, DT_RELA, TARGET, 0, relative_type(profile), addend);
            let image = decode(&fixture, Rc::new(State::default()), base)
                .relocate()
                .unwrap();
            assert_eq!(value(image.allocation(), profile, TARGET), expected);
            assert_eq!(image.entry(), Some(TargetAddress::new(base)));
        }
    }
}

#[test]
fn relative_relocation_preserves_full_64_bit_values_on_any_host() {
    for profile in [LoadProfile::riscv64(), LoadProfile::aarch64()] {
        let fixture = fixture(profile, DT_RELA, 1);
        let base = 0x1_0000_8000;
        let image = decode(&fixture, Rc::new(State::default()), base)
            .relocate()
            .unwrap();
        assert_eq!(value(image.allocation(), profile, TARGET), base);
    }
}

#[test]
fn relative_relocation_can_write_bss_and_form_values_outside_the_image() {
    for profile in PROFILES {
        let mut fixture = fixture(profile, DT_RELA, 1);
        fixture.ph(1, 3, 0x500);
        fixture.relocation(RELVA, DT_RELA, TARGET, 0, relative_type(profile), 0x70000);
        let image = decode(&fixture, Rc::new(State::default()), 0x8000)
            .relocate()
            .unwrap();
        assert_eq!(value(image.allocation(), profile, TARGET), 0x77000);
    }
}

#[test]
fn relative_relocation_ignores_none_records_for_rel_and_rela() {
    for profile in PROFILES {
        for kind in [DT_REL, DT_RELA] {
            let mut fixture = fixture(profile, kind, 1);
            fixture.relocation(RELVA, kind, u64::from(u32::MAX), 37, 0, -1);
            let state = Rc::new(State::default());
            let image = decode(&fixture, state.clone(), 0x8000).relocate().unwrap();
            assert_eq!(state.writes.get(), 0);
            assert_eq!(image.relocations().len(), 1);
        }
    }
}

#[test]
fn relative_relocation_accepts_static_images_without_dynamic_metadata() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.ph(2, 0, u64::from(PT_NOTE));
        let state = Rc::new(State::default());
        let decoded = load(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT,
            state.clone(),
        )
        .unwrap();
        state.writes.set(0);
        let image = decoded.relocate().unwrap();
        assert!(image.dynamic().is_none());
        assert!(image.relocations().is_empty());
        assert_eq!(state.writes.get(), 0);
    }
}

#[test]
fn relative_relocation_profile_rejects_other_types_and_implicit_addends() {
    for profile in PROFILES {
        let mut invalid_type = fixture(profile, DT_RELA, 2);
        let second = RELVA + relocation_size(profile.class(), DT_RELA);
        invalid_type.relocation(second, DT_RELA, TARGET + 8, 0, 0x7f, BASE as i64);
        rejects(
            &invalid_type,
            0x8000,
            LoadErrorKind::UnsupportedByProfile,
            TARGET + 8,
        );
        let implicit = fixture(profile, DT_REL, 1);
        rejects(
            &implicit,
            0x8000,
            LoadErrorKind::UnsupportedByProfile,
            TARGET,
        );
    }
}

#[test]
fn relative_relocation_requires_zero_symbol_index() {
    for profile in PROFILES {
        let mut fixture = fixture(profile, DT_RELA, 1);
        fixture.relocation(
            RELVA,
            DT_RELA,
            TARGET,
            1,
            relative_type(profile),
            BASE as i64,
        );
        rejects(&fixture, 0x8000, LoadErrorKind::BadElf, TARGET);
    }
}

#[test]
fn relative_relocation_rejects_read_only_holes_and_outside_targets() {
    for profile in PROFILES {
        for (target, kind) in [
            (BASE + 8, LoadErrorKind::PermissionConflict),
            (0x1800, LoadErrorKind::OutOfBounds),
            (0x3000, LoadErrorKind::OutOfBounds),
        ] {
            let mut fixture = fixture(profile, DT_RELA, 1);
            fixture.relocation(
                RELVA,
                DT_RELA,
                target,
                0,
                relative_type(profile),
                BASE as i64,
            );
            rejects(&fixture, 0x8000, kind, target);
        }
    }
}

#[test]
fn relative_relocation_requires_the_complete_word_in_one_segment() {
    for profile in PROFILES {
        let width = if profile.class() == ElfClass::Elf32 {
            4
        } else {
            8
        };
        let target = 0x2900 - width;
        let mut fixture = fixture(profile, DT_RELA, 1);
        fixture.ph(1, 3, 0x8ff);
        fixture.ph(1, 4, 0x8ff);
        fixture.relocation(
            RELVA,
            DT_RELA,
            target,
            0,
            relative_type(profile),
            BASE as i64,
        );
        rejects(&fixture, 0x8000, LoadErrorKind::OutOfBounds, target);
    }
}

#[test]
fn relative_relocation_checks_original_and_runtime_alignment() {
    for profile in PROFILES {
        let mut original = fixture(profile, DT_RELA, 1);
        original.relocation(
            RELVA,
            DT_RELA,
            TARGET + 1,
            0,
            relative_type(profile),
            BASE as i64,
        );
        rejects(
            &original,
            0x8000,
            LoadErrorKind::InvalidAlignment,
            TARGET + 1,
        );
        let mut runtime = fixture(profile, DT_RELA, 1);
        let (start, stride, offset, len) = match profile.class() {
            ElfClass::Elf32 => (52, 32, 28, 4),
            ElfClass::Elf64 => (64, 56, 48, 8),
        };
        for index in 0..2 {
            runtime.number(start + index * stride + offset, 1, len);
        }
        let base = if profile.class() == ElfClass::Elf32 {
            0x8002
        } else {
            0x8004
        };
        rejects(&runtime, base, LoadErrorKind::InvalidAlignment, TARGET);
    }
}

#[test]
fn relative_relocation_rejects_negative_and_width_overflow_results() {
    for profile in PROFILES {
        let mut negative = fixture(profile, DT_RELA, 1);
        negative.relocation(RELVA, DT_RELA, TARGET, 0, relative_type(profile), -0x7001);
        rejects(&negative, 0x8000, LoadErrorKind::IntegerOverflow, TARGET);
        let (base, addend) = if profile.class() == ElfClass::Elf32 {
            (0xffff_0000, i64::from(i32::MAX))
        } else {
            (u64::MAX - 0x3fff, 0x8000)
        };
        let mut overflow = fixture(profile, DT_RELA, 1);
        overflow.relocation(RELVA, DT_RELA, TARGET, 0, relative_type(profile), addend);
        rejects(&overflow, base, LoadErrorKind::IntegerOverflow, TARGET);
    }
}

#[test]
fn relative_relocation_rejects_duplicate_writes_before_any_mutation() {
    for profile in PROFILES {
        let mut fixture = fixture(profile, DT_RELA, 2);
        let second = RELVA + relocation_size(profile.class(), DT_RELA);
        fixture.relocation(
            second,
            DT_RELA,
            TARGET,
            0,
            relative_type(profile),
            BASE as i64,
        );
        rejects(&fixture, 0x8000, LoadErrorKind::BadElf, TARGET);
    }
}

#[test]
fn relative_relocation_checks_later_records_before_writing_earlier_ones() {
    for profile in PROFILES {
        let mut fixture = fixture(profile, DT_RELA, 2);
        let second = RELVA + relocation_size(profile.class(), DT_RELA);
        fixture.relocation(
            second,
            DT_RELA,
            BASE,
            0,
            relative_type(profile),
            BASE as i64,
        );
        rejects(&fixture, 0x8000, LoadErrorKind::PermissionConflict, BASE);
    }
}

#[test]
fn relative_relocation_backend_failure_drops_partially_modified_mapping_once() {
    for profile in PROFILES {
        for failing_write in [1, 2] {
            let fixture = fixture(profile, DT_RELA, 2);
            let state = Rc::new(State::default());
            let decoded = decode(&fixture, state.clone(), 0x8000);
            state.fail_write.set(Some(failing_write));
            let error = failure(decoded.relocate());
            assert_eq!(error.kind(), LoadErrorKind::Io);
            assert_eq!(error.stage(), Some(LoadStage::Relocate));
            assert!(
                matches!(error.context(), ErrorContext::Relocation { target, .. }
                if target.get() == TARGET + (failing_write as u64 - 1) * 8)
            );
            assert_eq!(state.writes.get(), failing_write);
            assert_eq!(state.live.get(), 0);
            assert_eq!(state.drops.get(), 1);
        }
    }
}
