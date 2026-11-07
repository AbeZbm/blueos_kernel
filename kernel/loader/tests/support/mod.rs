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

//! Backends shared by unit tests and the external integration runner.
//! The parent binds `loader` to the loader API; no production module includes this code.

use super::loader;

mod memory;
mod reader;

pub use memory::{FlatImageAllocation, MemoryMapper, MemoryRegion, ProtectionRange};
pub use reader::SliceElfReader;
