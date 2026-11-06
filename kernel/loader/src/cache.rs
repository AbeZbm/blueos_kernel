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

//! Host instruction-cache synchronization, independent of the ELF architecture.

use crate::{memory::TargetRange, LoadResult};

/// Makes completed code writes visible wherever this image may execute.
///
/// Ranges use target execution addresses, which need not be local pointers.
/// The loader keeps the mapping alive throughout the call. Implementations
/// must validate platform requirements before using native maintenance, order
/// preceding data writes, and synchronize instruction fetch as needed.
///
/// Success must cover every execution context where the host permits the
/// image to run. A local instruction fence is sufficient only when the host
/// restricts execution accordingly; other contexts require host coordination.
/// Cache-coherent hosts may omit maintenance only when their instruction
/// publication rules actually permit it. There is no default no-op adapter.
pub trait CodeCache {
    fn synchronize(&mut self, executable: TargetRange) -> LoadResult<()>;
}
