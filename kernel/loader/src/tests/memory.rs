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

//! Logical layout validation and the flat memory backend's safety boundaries.

use crate::{
    error::{ErrorContext, LoadErrorKind},
    memory::{
        AllocationOffset, ImageAllocator, ImageLayout, ImageMapping, MemoryMapper,
        MemoryPermissions, MemoryRegion, Placement, ProtectionLevel, SegmentLayout, TargetAddress,
        TargetRange,
    },
};
use alloc::{boxed::Box, vec};
use blueos_infra::storage::Storage;
use blueos_test_macro::test;
use core::alloc::Layout;

fn segment(allocation_offset: u64, len: u64) -> SegmentLayout {
    SegmentLayout::new(
        AllocationOffset::new(allocation_offset),
        len,
        MemoryPermissions::READ,
    )
}

fn fixed(base: u64, size: u64) -> ImageLayout {
    ImageLayout::new(
        Placement::Fixed(TargetRange::new(TargetAddress::new(base), size)),
        size,
        16,
        vec![segment(0, size)],
    )
    .unwrap()
}

fn fixed_mapper(
    permissions: MemoryPermissions,
) -> (MemoryMapper, *mut u8, &'static [MemoryRegion]) {
    // Bounded static fixtures: both the region declaration and its backing
    // must outlive every mapper that can borrow it.
    let storage = Box::leak(Box::new(
        Storage::try_from_layout(Layout::from_size_align(256, 64).unwrap()).unwrap(),
    ));
    let base = storage.base();
    // SAFETY: storage owns 256 writable bytes. No Rust slice aliases them.
    unsafe { core::ptr::write_bytes(base, 0xa5, 256) };
    // SAFETY: leaked backing stays mapped; the test accesses it exclusively
    // through this mapper until the allocation handle is returned.
    let region = unsafe { MemoryRegion::new(base as usize, base as usize + 256, permissions) };
    let regions = Box::leak(Box::new([region]));
    (MemoryMapper::new(Some(regions)), base, regions)
}

#[test]
fn image_layout_rejects_invalid_reservations_and_segments() {
    let cases = [
        (
            Placement::Anywhere,
            0,
            16,
            vec![segment(0, 1)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Anywhere,
            64,
            0,
            vec![segment(0, 1)],
            LoadErrorKind::InvalidAlignment,
        ),
        (
            Placement::Anywhere,
            64,
            3,
            vec![segment(0, 1)],
            LoadErrorKind::InvalidAlignment,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![segment(0, 0)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![segment(8, 32), segment(16, 4)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![segment(32, 8), segment(0, 8)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![segment(63, 2)],
            LoadErrorKind::OutOfBounds,
        ),
        (
            Placement::Anywhere,
            64,
            16,
            vec![segment(u64::MAX, 2)],
            LoadErrorKind::IntegerOverflow,
        ),
        (
            Placement::Fixed(TargetRange::new(TargetAddress::new(0x1000), 63)),
            64,
            16,
            vec![segment(0, 64)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Fixed(TargetRange::new(TargetAddress::new(0x1001), 64)),
            64,
            16,
            vec![segment(0, 64)],
            LoadErrorKind::IncorrectLayout,
        ),
        (
            Placement::Fixed(TargetRange::new(TargetAddress::new(u64::MAX - 15), 32)),
            32,
            16,
            vec![segment(0, 32)],
            LoadErrorKind::IntegerOverflow,
        ),
    ];
    for (placement, size, align, segments, kind) in cases {
        assert_eq!(
            ImageLayout::new(placement, size, align, segments)
                .unwrap_err()
                .kind(),
            kind
        );
    }
    let layout = ImageLayout::new(
        Placement::Anywhere,
        128,
        16,
        vec![segment(0, 16), segment(16, 16), segment(96, 32)],
    )
    .unwrap();
    assert_eq!(layout.segments().len(), 3);
}

#[test]
fn allocation_offsets_report_addition_overflow() {
    let error = AllocationOffset::new(u64::MAX).checked_add(1).unwrap_err();
    assert_eq!(error.kind(), LoadErrorKind::IntegerOverflow);
    assert!(matches!(
        error.context(),
        ErrorContext::MemoryAccess {
            offset: u64::MAX,
            len: 1,
            ..
        }
    ));
}

#[test]
fn flat_allocations_own_independent_backing_beyond_the_factory_lifetime() {
    let layout = ImageLayout::new(Placement::Anywhere, 128, 64, vec![segment(0, 128)]).unwrap();
    let (mut allocation, next) = {
        let mut memory = MemoryMapper::new(None);
        (
            memory.prepare_image(&layout).unwrap(),
            memory.prepare_image(&layout).unwrap(),
        )
    };
    assert_eq!(allocation.base().get() % 64, 0);
    let mut bytes = [0xff; 128];
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0; 128]);
    allocation
        .write(AllocationOffset::new(16), &[1, 2, 3, 4])
        .unwrap();
    allocation.zero(AllocationOffset::new(17), 2).unwrap();
    allocation
        .read(AllocationOffset::new(16), &mut bytes[..4])
        .unwrap();
    assert_eq!(&bytes[..4], &[1, 0, 0, 4]);

    assert_ne!(allocation.base(), next.base());
    next.read(AllocationOffset::new(16), &mut bytes[..4])
        .unwrap();
    assert_eq!(&bytes[..4], &[0; 4]);
    drop(next);
    allocation
        .read(AllocationOffset::new(16), &mut bytes[..4])
        .unwrap();
    assert_eq!(&bytes[..4], &[1, 0, 0, 4]);
}

#[test]
fn flat_mapper_rejects_invalid_host_layout_without_retaining_resources() {
    let mut memory = MemoryMapper::new(None);
    let bad = ImageLayout::new(Placement::Anywhere, u64::MAX, 16, vec![segment(0, 1)]).unwrap();
    assert!(memory.prepare_image(&bad).is_err());
    let good = ImageLayout::new(Placement::Anywhere, 16, 16, vec![segment(0, 16)]).unwrap();
    drop(memory.prepare_image(&good).unwrap());
}

#[test]
fn flat_allocation_checks_bounds_and_overflow_for_each_access() {
    let layout = ImageLayout::new(Placement::Anywhere, 64, 16, vec![segment(0, 64)]).unwrap();
    let mut allocation = MemoryMapper::new(None).prepare_image(&layout).unwrap();
    for (offset, len) in [(63, 2), (65, 0), (u64::MAX, 2)] {
        let mut bytes = [0; 2];
        assert!(allocation
            .read(AllocationOffset::new(offset), &mut bytes[..len as usize])
            .is_err());
        assert!(allocation
            .write(AllocationOffset::new(offset), &bytes[..len as usize])
            .is_err());
        assert!(allocation.zero(AllocationOffset::new(offset), len).is_err());
    }
    allocation.read(AllocationOffset::new(64), &mut []).unwrap();
    allocation.write(AllocationOffset::new(64), &[]).unwrap();
    allocation.zero(AllocationOffset::new(64), 0).unwrap();
}

#[test]
fn fixed_mapper_requires_read_write_authorization_before_mutation() {
    for permissions in [
        MemoryPermissions::READ,
        MemoryPermissions::WRITE,
        MemoryPermissions::NONE,
    ] {
        let (mut memory, base, _) = fixed_mapper(permissions);
        let error = memory
            .prepare_image(&fixed(base as usize as u64, 128))
            .unwrap_err();
        assert_eq!(error.kind(), LoadErrorKind::PermissionConflict);
        // SAFETY: preparation failed before mutation; no live allocation exists.
        assert_eq!(unsafe { *base }, 0xa5);
    }
    let (mut memory, base, _) =
        fixed_mapper(MemoryPermissions::READ.bitor(MemoryPermissions::WRITE));
    assert_eq!(
        memory
            .prepare_image(&fixed(base as usize as u64, 272))
            .unwrap_err()
            .kind(),
        LoadErrorKind::OutOfBounds
    );
    assert!(memory.prepare_image(&fixed(0, 16)).is_err());
    // SAFETY: neither rejected preparation acquired or modified the region.
    assert_eq!(unsafe { *base }, 0xa5);
    drop(
        memory
            .prepare_image(&fixed(base as usize as u64, 128))
            .unwrap(),
    );
}

#[test]
fn fixed_allocation_drop_preserves_bytes_and_next_preparation_resets_only_its_span() {
    let (mut memory, base, _) =
        fixed_mapper(MemoryPermissions::READ.bitor(MemoryPermissions::WRITE));
    let layout = fixed(base as usize as u64, 128);
    let mut allocation = memory.prepare_image(&layout).unwrap();
    let mut bytes = [0xff; 128];
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0; 128]);
    allocation.write(AllocationOffset::new(0), &[7]).unwrap();
    drop(allocation);
    // SAFETY: no allocation is live. Drop ended the borrow without restoring bytes.
    assert_eq!(unsafe { *base }, 7);
    let allocation = memory.prepare_image(&layout).unwrap();
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0; 128]);
    drop(allocation);
    // SAFETY: the unused tail of the authorized region was never borrowed or changed.
    assert_eq!(unsafe { *base.add(128) }, 0xa5);
}

#[test]
fn fixed_allocation_retains_exclusive_region_across_mapper_instances() {
    let (allocation, mut other, layout) = {
        let (mut memory, base, regions) =
            fixed_mapper(MemoryPermissions::READ.bitor(MemoryPermissions::WRITE));
        let layout = fixed(base as usize as u64, 128);
        let mut allocation = memory.prepare_image(&layout).unwrap();
        allocation.write(AllocationOffset::new(0), &[7]).unwrap();
        assert!(memory.prepare_image(&layout).is_err());
        let mut other = MemoryMapper::new(Some(regions));
        assert!(other.prepare_image(&layout).is_err());
        (allocation, other, layout)
    };
    assert!(other.prepare_image(&layout).is_err());
    let mut byte = [0];
    allocation
        .read(AllocationOffset::new(0), &mut byte)
        .unwrap();
    assert_eq!(byte, [7]); // Rejected attempts did not clear an active image.
    drop(allocation);
    let allocation = other.prepare_image(&layout).unwrap();
    allocation
        .read(AllocationOffset::new(0), &mut byte)
        .unwrap();
    assert_eq!(byte, [0]);
}

#[test]
fn flat_protection_restricts_mapper_reads_writes_and_zeroing() {
    let rw = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
    let (mut memory, base, _) = fixed_mapper(rw);
    let mut allocation = memory
        .prepare_image(&fixed(base as usize as u64, 64))
        .unwrap();
    allocation
        .write(AllocationOffset::new(0), &[7; 64])
        .unwrap();
    allocation
        .set_permissions(AllocationOffset::new(0), 16, MemoryPermissions::READ)
        .unwrap();
    allocation
        .set_permissions(AllocationOffset::new(32), 32, MemoryPermissions::NONE)
        .unwrap();
    assert_eq!(allocation.protection_level(), ProtectionLevel::LogicalOnly);
    allocation
        .read(AllocationOffset::new(8), &mut [0; 24])
        .unwrap();
    allocation
        .write(AllocationOffset::new(16), &[9; 16])
        .unwrap();
    allocation.zero(AllocationOffset::new(16), 16).unwrap();
    for offset in [0, 32] {
        assert_eq!(
            allocation
                .write(AllocationOffset::new(offset), &[1])
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
        assert_eq!(
            allocation
                .zero(AllocationOffset::new(offset), 1)
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
    }
    assert_eq!(
        allocation
            .write(AllocationOffset::new(8), &[1; 24])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
    assert_eq!(
        allocation
            .read(AllocationOffset::new(31), &mut [0; 2])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
    // Empty operations do not touch a byte, even at the end of a NONE range.
    allocation.read(AllocationOffset::new(64), &mut []).unwrap();
    allocation.write(AllocationOffset::new(64), &[]).unwrap();
    allocation.zero(AllocationOffset::new(64), 0).unwrap();
    drop(allocation);
    let allocation = memory
        .prepare_image(&fixed(base as usize as u64, 64))
        .unwrap();
    let mut bytes = [1; 64];
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [0; 64]);
}

#[test]
fn flat_protection_rejects_invalid_updates_without_changing_permissions() {
    let rw = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
    let (mut memory, base, _) = fixed_mapper(rw);
    let mut allocation = memory
        .prepare_image(&fixed(base as usize as u64, 64))
        .unwrap();
    allocation
        .set_permissions(AllocationOffset::new(0), 64, MemoryPermissions::READ)
        .unwrap();
    for (offset, len, kind) in [
        (0, 65, LoadErrorKind::OutOfBounds),
        (65, 0, LoadErrorKind::OutOfBounds),
        (65, 1, LoadErrorKind::OutOfBounds),
        (64, 1, LoadErrorKind::OutOfBounds),
        (u64::MAX, 2, LoadErrorKind::IntegerOverflow),
        (1, u64::MAX, LoadErrorKind::IntegerOverflow),
    ] {
        let error = allocation
            .set_permissions(AllocationOffset::new(offset), len, rw)
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert!(
            matches!(error.context(), ErrorContext::MemoryAccess { offset: actual_offset, len: actual_len, .. }
            if *actual_offset == offset && *actual_len == len)
        );
        assert_eq!(
            allocation
                .write(AllocationOffset::new(0), &[1])
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
        allocation
            .read(AllocationOffset::new(0), &mut [0; 64])
            .unwrap();
    }
    for offset in [0, 64] {
        allocation
            .set_permissions(AllocationOffset::new(offset), 0, rw)
            .unwrap();
    }
    assert_eq!(
        allocation
            .write(AllocationOffset::new(63), &[1])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
}

#[test]
fn flat_protection_cannot_exceed_fixed_region_authorization() {
    let rw = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
    let (mut memory, base, _) = fixed_mapper(rw);
    let layout = fixed(base as usize as u64, 64);
    let mut allocation = memory.prepare_image(&layout).unwrap();
    let rx = MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE);
    assert_eq!(
        allocation
            .set_permissions(AllocationOffset::new(16), 16, rx)
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
    allocation.write(AllocationOffset::new(0), &[1]).unwrap();
    allocation
        .set_permissions(AllocationOffset::new(0), 64, MemoryPermissions::NONE)
        .unwrap();
    drop(allocation);
    let allocation = memory.prepare_image(&layout).unwrap();
    let mut byte = [1];
    allocation
        .read(AllocationOffset::new(0), &mut byte)
        .unwrap();
    assert_eq!(byte, [0]);
}

#[test]
fn flat_protection_partial_updates_preserve_and_restore_neighboring_permissions() {
    let rw = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
    let (mut memory, base, _) = fixed_mapper(rw);
    let mut allocation = memory
        .prepare_image(&fixed(base as usize as u64, 64))
        .unwrap();
    allocation
        .set_permissions(AllocationOffset::new(16), 32, MemoryPermissions::READ)
        .unwrap();
    allocation
        .write(AllocationOffset::new(0), &[1; 16])
        .unwrap();
    allocation
        .write(AllocationOffset::new(48), &[1; 16])
        .unwrap();
    assert_eq!(
        allocation
            .write(AllocationOffset::new(16), &[1])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );

    allocation
        .set_permissions(AllocationOffset::new(24), 8, MemoryPermissions::NONE)
        .unwrap();
    allocation
        .read(AllocationOffset::new(16), &mut [0; 8])
        .unwrap();
    allocation
        .read(AllocationOffset::new(32), &mut [0; 16])
        .unwrap();
    assert_eq!(
        allocation
            .read(AllocationOffset::new(24), &mut [0; 1])
            .unwrap_err()
            .kind(),
        LoadErrorKind::PermissionConflict
    );
    allocation
        .set_permissions(AllocationOffset::new(24), 8, rw)
        .unwrap();
    allocation
        .write(AllocationOffset::new(24), &[1; 8])
        .unwrap();
    for offset in [16, 32] {
        assert_eq!(
            allocation
                .write(AllocationOffset::new(offset), &[1])
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
    }
    // Replace across several old boundaries, preserving both outside ends.
    allocation
        .set_permissions(AllocationOffset::new(8), 48, rw)
        .unwrap();
    allocation
        .write(AllocationOffset::new(0), &[7; 64])
        .unwrap();
    let mut bytes = [0; 64];
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(bytes, [7; 64]);
}

#[test]
fn flat_protection_overlapping_updates_match_a_bytewise_permission_model() {
    let rw = MemoryPermissions::READ.bitor(MemoryPermissions::WRITE);
    let (mut memory, base, _) = fixed_mapper(rw);
    let mut allocation = memory
        .prepare_image(&fixed(base as usize as u64, 64))
        .unwrap();
    let mut expected = [rw; 64];
    for (start, len, permissions) in [
        (16, 32, MemoryPermissions::READ),
        (24, 8, MemoryPermissions::NONE),
        (4, 48, MemoryPermissions::WRITE),
        (20, 36, rw),
        (10, 16, MemoryPermissions::NONE),
        (0, 64, MemoryPermissions::READ),
        (0, 64, rw),
    ] {
        allocation
            .set_permissions(AllocationOffset::new(start), len, permissions)
            .unwrap();
        expected[start as usize..(start + len) as usize].fill(permissions);
        for (index, permissions) in expected.iter().enumerate() {
            let offset = AllocationOffset::new(index as u64);
            assert_eq!(
                allocation.read(offset, &mut [0]).is_ok(),
                permissions.contains(MemoryPermissions::READ)
            );
            assert_eq!(
                allocation.write(offset, &[1]).is_ok(),
                permissions.contains(MemoryPermissions::WRITE)
            );
            assert_eq!(
                allocation.zero(offset, 1).is_ok(),
                permissions.contains(MemoryPermissions::WRITE)
            );
        }
    }
}

#[test]
fn preparation_grants_read_write_before_applying_read_only_or_executable_permissions() {
    let rx = MemoryPermissions::READ.bitor(MemoryPermissions::EXECUTE);
    let layout = ImageLayout::new(
        Placement::Anywhere,
        128,
        16,
        vec![
            SegmentLayout::new(AllocationOffset::new(0), 64, rx),
            SegmentLayout::new(AllocationOffset::new(64), 64, MemoryPermissions::READ),
        ],
    )
    .unwrap();
    let mut allocation = MemoryMapper::new(None).prepare_image(&layout).unwrap();
    allocation
        .write(AllocationOffset::new(0), &[7; 128])
        .unwrap();
    allocation.zero(AllocationOffset::new(0), 64).unwrap();
    let mut bytes = [0; 128];
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
    assert_eq!(&bytes[..64], &[0; 64]);
    assert_eq!(&bytes[64..], &[7; 64]);
    allocation
        .set_permissions(AllocationOffset::new(0), 64, rx)
        .unwrap();
    allocation
        .set_permissions(AllocationOffset::new(64), 64, MemoryPermissions::READ)
        .unwrap();
    for offset in [0, 64] {
        assert_eq!(
            allocation
                .write(AllocationOffset::new(offset), &[1])
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
        assert_eq!(
            allocation
                .zero(AllocationOffset::new(offset), 1)
                .unwrap_err()
                .kind(),
            LoadErrorKind::PermissionConflict
        );
    }
    allocation
        .read(AllocationOffset::new(0), &mut bytes)
        .unwrap();
}
