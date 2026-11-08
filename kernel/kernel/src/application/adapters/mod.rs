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

//! Platform adapters that bind the loader's neutral contracts to the kernel.

pub mod code_cache;
pub mod flat_memory;
pub mod memory_reader;

pub use code_cache::KernelCodeCache;
pub use flat_memory::{FlatImageAllocation, MemoryMapper, MemoryRegion, ProtectionRange};
pub use memory_reader::SliceElfReader;
