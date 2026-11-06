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

//! Lifecycle plans use relocated target pointers and never execute fixture code.

use super::{failure, plan, tags, Allocation, Allocator, Fixture, State, BASE, PROFILES, RELVA};
use crate::{
    error::{ErrorContext, LimitKind, LoadErrorKind, LoadStage},
    image::RelocatedImage,
    memory::{TargetAddress, TargetRange},
    profile::{ElfClass, ElfData, LoadLimits, LoadProfile, LoadPurpose},
    CodeCache, LoadResult,
};
use alloc::{rc::Rc, vec, vec::Vec};
use blueos_test_macro::test;
use goblin::elf::{
    dynamic::{
        DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NULL,
        DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_REL, DT_RELA,
    },
    program_header::PT_NOTE,
    reloc::{R_AARCH64_RELATIVE, R_RISCV_RELATIVE},
};

const ARRAY: u64 = 0x2600;

#[derive(Default)]
struct Cache {
    calls: usize,
}

impl CodeCache for Cache {
    fn synchronize(&mut self, range: TargetRange) -> LoadResult<()> {
        range.end()?;
        self.calls += 1;
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

fn width(profile: LoadProfile) -> u64 {
    match profile.class() {
        ElfClass::Elf32 => 4,
        ElfClass::Elf64 => 8,
    }
}

fn addresses(values: &[u64]) -> Vec<TargetAddress> {
    values.iter().copied().map(TargetAddress::new).collect()
}

#[test]
fn lifecycle_orders_direct_calls_and_arrays_without_running_code() {
    for profile in PROFILES {
        let size = width(profile);
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_PREINIT_ARRAY, ARRAY),
                (DT_PREINIT_ARRAYSZ, 2 * size),
                (DT_INIT, BASE + 16),
                (DT_INIT_ARRAY, ARRAY + 0x40),
                (DT_INIT_ARRAYSZ, 2 * size),
                (DT_FINI, BASE + 56),
                (DT_FINI_ARRAY, ARRAY + 0x80),
                (DT_FINI_ARRAYSZ, 2 * size),
                (DT_NULL, 0),
            ],
        );
        for (array, values) in [
            (ARRAY, [0x8000, 0x8008]),
            (ARRAY + 0x40, [0x8018, 0x8020]),
            (ARRAY + 0x80, [0x8028, 0x8030]),
        ] {
            for (index, value) in values.into_iter().enumerate() {
                fixture.word(fixture.file_offset(array + index as u64 * size), value);
            }
        }
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        assert_eq!(state.reads.get(), 0);
        let image = image.seal(&mut Cache::default()).unwrap();
        assert_eq!(image.lifecycle().preinit(), addresses(&[0x8000, 0x8008]));
        assert_eq!(
            image.lifecycle().init(),
            addresses(&[0x8010, 0x8018, 0x8020])
        );
        assert_eq!(
            image.lifecycle().fini(),
            addresses(&[0x8030, 0x8028, 0x8038])
        );
        assert_eq!(state.reads.get(), 6);
        assert_eq!(state.drops.get(), 0);
        drop(image);
        assert_eq!(state.drops.get(), 1);
        assert_eq!(state.live.get(), 0);
    }
}

#[test]
fn lifecycle_reads_arrays_after_relative_relocation() {
    for profile in PROFILES {
        let mut dynamic = tags(profile.class(), DT_RELA, RELVA, 1);
        dynamic.extend([
            (DT_INIT_ARRAY, ARRAY),
            (DT_INIT_ARRAYSZ, width(profile)),
            (DT_NULL, 0),
        ]);
        let mut fixture = Fixture::new(profile, &dynamic);
        let relative = if profile.machine() == LoadProfile::aarch64().machine() {
            R_AARCH64_RELATIVE
        } else {
            R_RISCV_RELATIVE
        };
        fixture.relocation(RELVA, DT_RELA, ARRAY, 0, relative, (BASE + 8) as i64);
        // This original value is deliberately invalid as a callback address.
        fixture.word(fixture.file_offset(ARRAY), 0xdead);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
        let reads = state.reads.get();
        let image = image.seal(&mut Cache::default()).unwrap();
        assert_eq!(image.lifecycle().init(), addresses(&[0x8008]));
        assert_eq!(state.reads.get(), reads + 1);
    }
}

#[test]
fn lifecycle_handles_target_endian_and_full_width_pointers() {
    for mut profile in PROFILES {
        profile = LoadProfile::new(
            profile.class(),
            ElfData::Big,
            profile.machine(),
            profile.header_flags(),
            profile.entry_mode(),
        );
        let base = if profile.class() == ElfClass::Elf32 {
            0x8000
        } else {
            0x1_0000_8000
        };
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_INIT_ARRAY, ARRAY),
                (DT_INIT_ARRAYSZ, width(profile)),
                (DT_FINI, BASE + 16),
                (DT_NULL, 0),
            ],
        );
        fixture.word(fixture.file_offset(ARRAY), base + 8);
        let image = relocated(&fixture, Rc::default(), base, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert_eq!(image.lifecycle().init(), addresses(&[base + 8]));
        assert_eq!(image.lifecycle().fini(), addresses(&[base + 16]));
    }
}

#[test]
fn lifecycle_allows_empty_plans_and_unused_array_slots() {
    for profile in PROFILES {
        let size = width(profile);
        let sentinel = if size == 4 {
            u64::from(u32::MAX)
        } else {
            u64::MAX
        };
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_INIT, 0),
                (DT_FINI, 0),
                (DT_INIT_ARRAY, ARRAY),
                (DT_INIT_ARRAYSZ, 3 * size),
                (DT_NULL, 0),
            ],
        );
        for (index, value) in [0, sentinel, 0x8008].into_iter().enumerate() {
            fixture.word(fixture.file_offset(ARRAY + index as u64 * size), value);
        }
        let image = relocated(&fixture, Rc::default(), 0x8000, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert!(image.lifecycle().preinit().is_empty());
        assert_eq!(image.lifecycle().init(), addresses(&[0x8008]));
        assert!(image.lifecycle().fini().is_empty());
        let fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert!(image.lifecycle().init().is_empty());
        assert!(image.lifecycle().fini().is_empty());
        assert_eq!(state.reads.get(), 0);
        drop(image);
        let mut fixture = Fixture::new(profile, &[(DT_NULL, 0)]);
        fixture.ph(2, 0, u64::from(PT_NOTE));
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert!(image.dynamic().is_none());
        assert!(image.lifecycle().preinit().is_empty());
        assert!(image.lifecycle().init().is_empty());
        assert!(image.lifecycle().fini().is_empty());
        assert_eq!(state.reads.get(), 0);
    }
}

#[test]
fn lifecycle_validates_array_geometry_before_allocating() {
    for profile in PROFILES {
        let size = width(profile);
        for (dynamic, tag, value) in [
            (vec![(DT_INIT_ARRAY, ARRAY)], DT_INIT_ARRAY, ARRAY),
            (vec![(DT_INIT_ARRAYSZ, size)], DT_INIT_ARRAYSZ, size),
            (
                vec![(DT_INIT_ARRAY, ARRAY), (DT_INIT_ARRAYSZ, size + 1)],
                DT_INIT_ARRAYSZ,
                size + 1,
            ),
            (
                vec![(DT_INIT_ARRAY, ARRAY + 1), (DT_INIT_ARRAYSZ, size)],
                DT_INIT_ARRAY,
                ARRAY + 1,
            ),
            (
                vec![(DT_INIT_ARRAY, 0x1ff8), (DT_INIT_ARRAYSZ, 2 * size)],
                DT_INIT_ARRAY,
                0x1ff8,
            ),
            (
                vec![(DT_INIT_ARRAY, 0x28f8), (DT_INIT_ARRAYSZ, 3 * size)],
                DT_INIT_ARRAY,
                0x28f8,
            ),
        ] {
            let mut dynamic = dynamic;
            dynamic.push((DT_NULL, 0));
            let fixture = Fixture::new(profile, &dynamic);
            let state = Rc::new(State::default());
            let error = failure(plan(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT,
                state.clone(),
            ));
            assert_eq!(error.kind(), LoadErrorKind::BadElf);
            assert_eq!(error.stage(), Some(LoadStage::Plan));
            assert!(
                matches!(error.context(), ErrorContext::DynamicTag {tag: t, value: v} if *t == tag && *v == value)
            );
            assert_eq!(state.prepares.get(), 0);
            assert_eq!(state.reader_drops.get(), 1);
        }
    }
}

#[test]
fn lifecycle_budget_counts_slots_and_direct_calls_before_allocation() {
    for profile in PROFILES {
        let fixture = Fixture::new(
            profile,
            &[
                (DT_INIT, BASE),
                (DT_FINI, BASE + 8),
                (DT_INIT_ARRAY, ARRAY),
                (DT_INIT_ARRAYSZ, 3 * width(profile)),
                (DT_NULL, 0),
            ],
        );
        let state = Rc::new(State::default());
        let error = failure(plan(
            &fixture,
            LoadPurpose::Executable,
            LoadLimits::DEFAULT.with_max_lifecycle_entries(4),
            state.clone(),
        ));
        assert_eq!(error.kind(), LoadErrorKind::ResourceLimit);
        assert!(matches!(
            error.context(),
            ErrorContext::Limit {
                resource: LimitKind::LifecycleEntryCount,
                actual: 5,
                maximum: 4,
            }
        ));
        assert_eq!(state.prepares.get(), 0);
        drop(
            plan(
                &fixture,
                LoadPurpose::Executable,
                LoadLimits::DEFAULT.with_max_lifecycle_entries(5),
                state,
            )
            .unwrap(),
        );
    }
}

#[test]
fn lifecycle_zero_length_and_bss_arrays_do_not_require_file_backing() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_PREINIT_ARRAY, 1),
                (DT_PREINIT_ARRAYSZ, 0),
                (DT_INIT_ARRAY, ARRAY),
                (DT_INIT_ARRAYSZ, 2 * width(profile)),
                (DT_NULL, 0),
            ],
        );
        fixture.ph(1, 3, 0x500); // The array is now in BSS and will be cleared by map().
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert!(image.lifecycle().preinit().is_empty());
        assert!(image.lifecycle().init().is_empty());
        assert_eq!(state.reads.get(), 2);
    }
}

#[test]
fn lifecycle_profile_rejects_shared_object_preinit() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_PREINIT_ARRAY, ARRAY),
                (DT_PREINIT_ARRAYSZ, 0),
                (DT_NULL, 0),
            ],
        );
        fixture.entry(0);
        let state = Rc::new(State::default());
        let error = failure(plan(
            &fixture,
            LoadPurpose::SharedObject,
            LoadLimits::DEFAULT,
            state.clone(),
        ));
        assert_eq!(error.kind(), LoadErrorKind::UnsupportedByProfile);
        assert!(matches!(
            error.context(),
            ErrorContext::DynamicTag {
                tag: DT_PREINIT_ARRAY,
                value: ARRAY
            }
        ));
        assert_eq!(state.prepares.get(), 0);
    }
}

#[test]
fn lifecycle_rejects_invalid_targets_and_releases_mapping() {
    for profile in PROFILES {
        for value in [0x8001, 0x8100, 0x9000, 0x8fff, 0x7ff8] {
            let mut fixture = Fixture::new(
                profile,
                &[
                    (DT_INIT_ARRAY, ARRAY),
                    (DT_INIT_ARRAYSZ, width(profile)),
                    (DT_NULL, 0),
                ],
            );
            fixture.word(fixture.file_offset(ARRAY), value);
            let state = Rc::new(State::default());
            let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
            let protects = state.protects.get();
            let mut cache = Cache::default();
            let error = failure(image.seal(&mut cache));
            assert_eq!(error.stage(), Some(LoadStage::Seal));
            assert!(
                matches!(error.context(), ErrorContext::DynamicTag {tag: DT_INIT_ARRAY, value: v} if *v == value)
            );
            assert_eq!(cache.calls, 0);
            assert_eq!(state.protects.get(), protects);
            assert_eq!(state.drops.get(), 1);
            assert_eq!(state.live.get(), 0);
        }
        for value in [
            BASE - 8,
            BASE + 0x100,
            BASE + 0x1000,
            u64::from(u32::MAX) - 7,
        ] {
            let fixture = Fixture::new(profile, &[(DT_INIT, value), (DT_NULL, 0)]);
            let state = Rc::new(State::default());
            let error = failure(
                relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable)
                    .seal(&mut Cache::default()),
            );
            assert_eq!(error.stage(), Some(LoadStage::Seal));
            assert_eq!(state.drops.get(), 1);
        }
        // A callback needs a complete instruction within its executable segment.
        let value = BASE + 0x100 - u64::from(profile.entry_mode().minimum_instruction_size());
        let mut fixture = Fixture::new(profile, &[(DT_INIT, value), (DT_NULL, 0)]);
        fixture.ph(0, 3, 0xff);
        fixture.ph(0, 4, 0xff);
        let error = failure(
            relocated(&fixture, Rc::default(), 0x8000, LoadPurpose::Executable)
                .seal(&mut Cache::default()),
        );
        assert_eq!(error.kind(), LoadErrorKind::OutOfBounds);
    }
}

#[test]
fn lifecycle_backend_read_failure_preserves_context_and_releases_mapping() {
    let profile = LoadProfile::riscv32();
    let mut fixture = Fixture::new(
        profile,
        &[
            (DT_INIT_ARRAY, ARRAY),
            (DT_INIT_ARRAYSZ, width(profile)),
            (DT_NULL, 0),
        ],
    );
    fixture.word(fixture.file_offset(ARRAY), 0x8000);
    let state = Rc::new(State::default());
    let image = relocated(&fixture, state.clone(), 0x8000, LoadPurpose::Executable);
    state.fail_read.set(Some(1));
    let error = failure(image.seal(&mut Cache::default()));
    assert_eq!(error.kind(), LoadErrorKind::Io);
    assert_eq!(error.stage(), Some(LoadStage::Seal));
    assert!(matches!(
        error.context(),
        ErrorContext::DynamicTag {
            tag: DT_REL,
            value: 0x1600,
        }
    ));
    assert_eq!(state.drops.get(), 1);
    assert_eq!(state.live.get(), 0);
}

#[test]
fn lifecycle_direct_address_can_relocate_to_runtime_zero() {
    for profile in PROFILES {
        let fixture = Fixture::new(profile, &[(DT_INIT, BASE), (DT_NULL, 0)]);
        let image = relocated(&fixture, Rc::default(), 0, LoadPurpose::Executable)
            .seal(&mut Cache::default())
            .unwrap();
        assert_eq!(image.lifecycle().init(), addresses(&[0]));
    }
}

#[test]
fn lifecycle_checks_runtime_array_alignment_with_weak_segment_alignment() {
    for profile in PROFILES {
        let size = width(profile);
        let base = 0x8000 + size / 2;
        let mut fixture = Fixture::new(
            profile,
            &[
                (DT_INIT_ARRAY, ARRAY),
                (DT_INIT_ARRAYSZ, size),
                (DT_NULL, 0),
            ],
        );
        let (start, stride, align, len) = match profile.class() {
            ElfClass::Elf32 => (52, 32, 28, 4),
            ElfClass::Elf64 => (64, 56, 48, 8),
        };
        for index in 0..2 {
            fixture.number(start + index * stride + align, 1, len);
        }
        let state = Rc::new(State::default());
        let image = relocated(&fixture, state.clone(), base, LoadPurpose::Executable);
        let error = failure(image.seal(&mut Cache::default()));
        assert_eq!(error.kind(), LoadErrorKind::InvalidAlignment);
        assert_eq!(error.stage(), Some(LoadStage::Seal));
        assert_eq!(state.reads.get(), 0);
        assert_eq!(state.drops.get(), 1);
    }
}

#[test]
fn lifecycle_shared_object_retains_init_and_fini_without_an_entry() {
    for profile in PROFILES {
        let mut fixture = Fixture::new(
            profile,
            &[(DT_INIT, BASE), (DT_FINI, BASE + 8), (DT_NULL, 0)],
        );
        fixture.entry(0);
        let image = relocated(&fixture, Rc::default(), 0x8000, LoadPurpose::SharedObject)
            .seal(&mut Cache::default())
            .unwrap();
        assert_eq!(image.entry(), None);
        assert!(image.lifecycle().preinit().is_empty());
        assert_eq!(image.lifecycle().init(), addresses(&[0x8000]));
        assert_eq!(image.lifecycle().fini(), addresses(&[0x8008]));
    }
}
