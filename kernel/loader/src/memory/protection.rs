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

//! Logical permission intervals and the backend's enforcement level.

use super::{AllocationOffset, MemoryPermissions};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProtectionLevel {
    /// Permissions are metadata; CPU accesses are not restricted by this backend.
    #[default]
    LogicalOnly,
    /// Permissions are enforced for the image's execution context.
    HardwareEnforced,
}

/// A nonempty permission range relative to the image allocation base.
///
/// Backends may use these records to track their current access rules.
/// Updating a mapping only requires the interval passed to `set_permissions`.
/// NONE spans need not have physical backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectionRange {
    allocation_offset: AllocationOffset,
    len: u64,
    permissions: MemoryPermissions,
}

impl ProtectionRange {
    pub const fn new(
        allocation_offset: AllocationOffset,
        len: u64,
        permissions: MemoryPermissions,
    ) -> Self {
        Self {
            allocation_offset,
            len,
            permissions,
        }
    }

    pub const fn allocation_offset(&self) -> AllocationOffset {
        self.allocation_offset
    }

    pub const fn len(&self) -> u64 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }
}
